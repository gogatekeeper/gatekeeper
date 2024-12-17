package utils

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/metrics"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2"
)

func VerifyToken(
	ctx context.Context,
	provider *oidc3.Provider,
	rawToken string,
	clientID string,
	skipClientIDCheck bool,
	skipIssuerCheck bool,
) (*oidc3.IDToken, error) {
	// This verifier with this configuration checks only signatures
	// we want to know if we are using valid token
	// bad is that Verify method doesn't check first signatures, so
	// we have to do it like this
	verifier := provider.Verifier(
		&oidc3.Config{
			ClientID:          clientID,
			SkipClientIDCheck: true,
			SkipIssuerCheck:   true,
			SkipExpiryCheck:   true,
		},
	)
	_, err := verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, errors.Join(apperrors.ErrTokenSignature, err)
	}

	// Now doing expiration check
	verifier = provider.Verifier(
		&oidc3.Config{
			ClientID:          clientID,
			SkipClientIDCheck: skipClientIDCheck,
			SkipIssuerCheck:   skipIssuerCheck,
			SkipExpiryCheck:   false,
		},
	)

	oToken, err := verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, err
	}

	return oToken, nil
}

func ParseRefreshToken(rawRefreshToken string) (*jwt.Claims, error) {
	refreshToken, err := jwt.ParseSigned(rawRefreshToken, constant.SignatureAlgs[:])
	if err != nil {
		return nil, err
	}

	stdRefreshClaims := &jwt.Claims{}
	err = refreshToken.UnsafeClaimsWithoutVerification(stdRefreshClaims)
	if err != nil {
		return nil, err
	}

	return stdRefreshClaims, nil
}

// GetRefreshedToken attempts to refresh the access token, returning the parsed token, optionally with a renewed
// refresh token and the time the access and refresh tokens expire
//
// NOTE: we may be able to extract the specific (non-standard) claim refresh_expires_in and refresh_expires
// from response.RawBody.
// When not available, keycloak provides us with the same (for now) expiry value for ID token.
func GetRefreshedToken(
	ctx context.Context,
	conf *oauth2.Config,
	httpClient *http.Client,
	oldRefreshToken string,
) (jwt.JSONWebToken, string, string, time.Time, time.Duration, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	start := time.Now()

	tkn, err := conf.TokenSource(ctx, &oauth2.Token{RefreshToken: oldRefreshToken}).Token()
	if err != nil {
		if strings.Contains(err.Error(), "invalid_grant") {
			return jwt.JSONWebToken{},
				"",
				"",
				time.Time{},
				time.Duration(0),
				apperrors.ErrRefreshTokenExpired
		}
		return jwt.JSONWebToken{},
			"",
			"",
			time.Time{},
			time.Duration(0),
			err
	}

	taken := time.Since(start).Seconds()
	metrics.OauthTokensMetric.WithLabelValues("renew").Inc()
	metrics.OauthLatencyMetric.WithLabelValues("renew").Observe(taken)

	token, err := jwt.ParseSigned(tkn.AccessToken, constant.SignatureAlgs[:])
	if err != nil {
		return jwt.JSONWebToken{},
			"",
			"",
			time.Time{},
			time.Duration(0),
			err
	}

	refreshToken, err := jwt.ParseSigned(tkn.RefreshToken, constant.SignatureAlgs[:])
	if err != nil {
		return jwt.JSONWebToken{},
			"",
			"",
			time.Time{},
			time.Duration(0),
			err
	}

	stdClaims := &jwt.Claims{}
	err = token.UnsafeClaimsWithoutVerification(stdClaims)
	if err != nil {
		return jwt.JSONWebToken{},
			"",
			"",
			time.Time{},
			time.Duration(0),
			err
	}

	refreshStdClaims := &jwt.Claims{}
	err = refreshToken.UnsafeClaimsWithoutVerification(refreshStdClaims)
	if err != nil {
		return jwt.JSONWebToken{},
			"",
			"",
			time.Time{},
			time.Duration(0),
			err
	}

	refreshExpiresIn := time.Until(refreshStdClaims.Expiry.Time())

	return *token,
		tkn.AccessToken,
		tkn.RefreshToken,
		stdClaims.Expiry.Time(),
		refreshExpiresIn,
		nil
}

// CheckClaim checks whether claim in userContext matches claimName, match. It can be String or Strings claim.
func CheckClaim(
	logger *zap.Logger,
	user *models.UserContext,
	claimName string,
	match *regexp.Regexp,
	resourceURL string,
) bool {
	errFields := []zapcore.Field{
		zap.String("claim", claimName),
		zap.String("access", "denied"),
		zap.String("userID", user.ID),
		zap.String("resource", resourceURL),
	}

	lLog := logger.With(errFields...)
	if _, found := user.Claims[claimName]; !found {
		lLog.Warn("the token does not have the claim")
		return false
	}

	switch claims := user.Claims[claimName].(type) {
	case []interface{}:
		for _, v := range claims {
			value, ok := v.(string)
			if !ok {
				lLog.Warn(
					"Problem while asserting claim",
					zap.String(
						"issued",
						fmt.Sprintf("%v", user.Claims[claimName]),
					),
					zap.String("required", match.String()),
				)

				return false
			}

			if match.MatchString(value) {
				return true
			}
		}

		lLog.Warn(
			"claim requirement does not match any element claim group in token",
			zap.String("issued", fmt.Sprintf("%v", user.Claims[claimName])),
			zap.String("required", match.String()),
		)

		return false
	case string:
		if match.MatchString(claims) {
			return true
		}

		lLog.Warn(
			"claim requirement does not match claim in token",
		)

		lLog.Debug(
			"claims",
			zap.String("issued", claims),
			zap.String("required", match.String()),
		)

		return false
	default:
		logger.Error(
			"unable to extract the claim from token not string or array of strings",
		)
	}

	lLog.Warn("unexpected error")
	return false
}

func VerifyOIDCTokens(
	ctx context.Context,
	provider *oidc3.Provider,
	clientID string,
	rawAccessToken string,
	rawIDToken string,
	skipClientIDCheck bool,
	skipIssuerCheck bool,
) (*oidc3.IDToken, *oidc3.IDToken, error) {
	var oIDToken *oidc3.IDToken
	var oAccToken *oidc3.IDToken
	var err error

	oIDToken, err = VerifyToken(ctx, provider, rawIDToken, clientID, false, false)
	if err != nil {
		return nil, nil, errors.Join(apperrors.ErrVerifyIDToken, err)
	}

	// check https://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken - at_hash
	// keycloak seems doesnt support yet at_hash
	// https://stackoverflow.com/questions/60818373/configure-keycloak-to-include-an-at-hash-claim-in-the-id-token
	if oIDToken.AccessTokenHash != "" {
		err = oIDToken.VerifyAccessToken(rawAccessToken)
		if err != nil {
			return nil, nil, errors.Join(apperrors.ErrAccTokenVerifyFailure, err)
		}
	}

	oAccToken, err = VerifyToken(
		ctx,
		provider,
		rawAccessToken,
		clientID,
		skipClientIDCheck,
		skipIssuerCheck,
	)
	if err != nil {
		return nil, nil, errors.Join(apperrors.ErrAccTokenVerifyFailure, err)
	}

	return oAccToken, oIDToken, nil
}

func NewOAuth2Config(
	clientID string,
	clientSecret string,
	authURL string,
	tokenURL string,
	scopes []string,
) func(redirectionURL string) *oauth2.Config {
	return func(redirectionURL string) *oauth2.Config {
		defaultScope := []string{"openid"}

		conf := &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
			RedirectURL: redirectionURL,
			Scopes:      append(scopes, defaultScope...),
		}

		return conf
	}
}
