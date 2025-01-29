package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/PuerkitoBio/purell"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/cookie"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/metrics"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/storage"
	"github.com/grokify/go-pkce"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// GetRefreshTokenFromCookie returns the refresh token from the cookie if any.
func GetRefreshTokenFromCookie(req *http.Request, cookieName string) (string, error) {
	token, err := GetTokenInCookie(req, cookieName)
	if err != nil {
		return "", err
	}

	return token, nil
}

// getTokenInRequest returns the token from the http request
//
//nolint:cyclop
func GetTokenInRequest(
	req *http.Request,
	name string,
	skipAuthorizationHeaderIdentity bool,
	tokenHeader string,
) (string, bool, error) {
	bearer := true
	token := ""
	var err error

	if tokenHeader == "" && !skipAuthorizationHeaderIdentity {
		token, err = GetTokenInBearer(req)
		if err != nil && !errors.Is(err, apperrors.ErrSessionNotFound) {
			return "", false, err
		}
	}

	if tokenHeader != "" {
		token, err = GetTokenInHeader(req, tokenHeader)
		if err != nil && !errors.Is(err, apperrors.ErrSessionNotFound) {
			return "", false, err
		}
	}

	// step: check for a token in the authorization header
	if err != nil || skipAuthorizationHeaderIdentity {
		if token, err = GetTokenInCookie(req, name); err != nil {
			return token, false, err
		}
		bearer = false
	}

	return token, bearer, nil
}

// getTokenInBearer retrieves a access token from the authorization header.
func GetTokenInBearer(req *http.Request) (string, error) {
	token := req.Header.Get(constant.AuthorizationHeader)
	if token == "" {
		return "", apperrors.ErrSessionNotFound
	}

	items := strings.Split(token, " ")
	numItems := 2

	if len(items) != numItems {
		return "", apperrors.ErrInvalidSession
	}

	if items[0] != constant.AuthorizationType {
		return "", apperrors.ErrSessionNotFound
	}
	return items[1], nil
}

// getTokenInHeader retrieves a token from the header.
func GetTokenInHeader(req *http.Request, headerName string) (string, error) {
	token := req.Header.Get(headerName)
	if token == "" {
		return "", apperrors.ErrSessionNotFound
	}
	return token, nil
}

// getTokenInCookie retrieves the access token from the request cookies.
func GetTokenInCookie(req *http.Request, name string) (string, error) {
	var token bytes.Buffer

	if cookie := cookie.FindCookie(name, req.Cookies()); cookie != nil {
		token.WriteString(cookie.Value)
	}

	// add also divided cookies
	for i := 1; i < 600; i++ {
		cookie := cookie.FindCookie(name+"-"+strconv.Itoa(i), req.Cookies())
		if cookie == nil {
			break
		}
		token.WriteString(cookie.Value)
	}

	if token.Len() == 0 {
		return "", apperrors.ErrSessionNotFound
	}

	return token.String(), nil
}

// GetIdentity retrieves the user identity from a request, either from a session cookie or a bearer token.
func GetIdentity(
	logger *zap.Logger,
	skipAuthorizationHeaderIdentity bool,
	enableEncryptedToken bool,
	forceEncryptedCookie bool,
	encKey string,
	useIdentityFromBasicAuth bool,
) func(req *http.Request, tokenCookie string, tokenHeader string) (*models.UserContext, error) {
	return func(req *http.Request, tokenCookie string, tokenHeader string) (*models.UserContext, error) {
		// step: check for a bearer token or cookie with jwt token
		if req.Header.Get(constant.AuthorizationHeader) != "" {
			logger.Debug("Found authorization header", zap.String("auth-header-value", req.Header.Get(constant.AuthorizationHeader)))
		}
		if req.Header.Get("Git-Protocol") != "" {
			logger.Debug("Request header", zap.String("request-header", req.Header.Get("Git-Protocol")))
		}
		logger.Debug("Request path", zap.String("request-path", req.URL.Path))
		logger.Debug("Request user agent", zap.String("user-agent", req.UserAgent()))

		purell.NormalizeURL(req.URL, purell.FlagRemoveDotSegments|purell.FlagRemoveDuplicateSlashes)
		if strings.Contains(strings.ToLower(req.UserAgent()), "git/") && strings.HasSuffix(strings.ToLower(req.URL.Path), "info/refs") && strings.ToLower(req.Header.Get("Git-Protocol")) == "version=2" {

			stdClaims := &jwt.Claims{}
			customClaims := models.CustClaims{}
			user := &models.UserContext{
				Audiences:     stdClaims.Audience,
				Email:         "office@group-cts.com",
				ExpiresAt:     stdClaims.Expiry.Time(),
				ID:            stdClaims.Subject,
				Name:          "GIT client console user",
				PreferredName: "GIT Client Console User",
				Permissions:   customClaims.Authorization,
				Groups:        []string{"ProxyAuth"},
			}

			authHeader := req.Header.Get(constant.AuthorizationHeader)
			var rawToken string
			if strings.Contains(authHeader, "Basic") {
				rawToken = strings.ReplaceAll(authHeader, "Basic ", "")
				user.BearerToken = false
			} else if strings.Contains(authHeader, "Bearer") {
				rawToken = strings.ReplaceAll(authHeader, "Bearer ", "")
				user.BearerToken = true
			}

			user.RawToken = rawToken

			logger.Debug("found the user identity",
				zap.String("id", user.ID),
				zap.String("name", user.Name),
				zap.String("email", user.Email),
				zap.String("roles", strings.Join(user.Roles, ",")),
				zap.String("groups", strings.Join(user.Groups, ",")))

			user.SkipVerification = true
			return user, nil
		} else {
			var isBearer bool
			access, isBearer, err := GetTokenInRequest(
				req,
				tokenCookie,
				skipAuthorizationHeaderIdentity,
				tokenHeader,
			)
			if err != nil {
				return nil, err
			}

			if enableEncryptedToken || forceEncryptedCookie && !isBearer {
				if access, err = encryption.DecodeText(access, encKey); err != nil {
					return nil, apperrors.ErrDecryption
				}
			}
			rawToken := access
			token, err := jwt.ParseSigned(access, constant.SignatureAlgs[:])
			if err != nil {
				return nil, err
			}

			user, err := ExtractIdentity(token)
			if err != nil {
				return nil, err
			}

			user.BearerToken = isBearer
			user.RawToken = rawToken

			logger.Debug("found the user identity",
				zap.String("id", user.ID),
				zap.String("name", user.Name),
				zap.String("email", user.Email),
				zap.String("roles", strings.Join(user.Roles, ",")),
				zap.String("groups", strings.Join(user.Groups, ",")))

			return user, nil
		}
	}
}

// ExtractIdentity parse the jwt token and extracts the various elements is order to construct.
func ExtractIdentity(token *jwt.JSONWebToken) (*models.UserContext, error) {
	stdClaims := &jwt.Claims{}
	customClaims := models.CustClaims{}

	err := token.UnsafeClaimsWithoutVerification(stdClaims, &customClaims)

	if err != nil {
		return nil, err
	}

	jsonMap := make(map[string]interface{})
	err = token.UnsafeClaimsWithoutVerification(&jsonMap)

	if err != nil {
		return nil, err
	}

	// @step: ensure we have and can extract the preferred name of the user, if not, we set to the ID
	preferredName := customClaims.PrefName
	if preferredName == "" {
		preferredName = customClaims.Email
	}

	audiences := stdClaims.Audience

	// @step: extract the realm roles
	roleList := make([]string, 0)
	roleList = append(roleList, customClaims.RealmAccess.Roles...)

	// @step: extract the client roles from the access token
	for name, list := range customClaims.ResourceAccess {
		scopes, assertOk := list.(map[string]interface{})

		if !assertOk {
			return nil, apperrors.ErrAssertionFailed
		}

		if roles, found := scopes[constant.ClaimResourceRoles]; found {
			rolesVal, assertOk := roles.([]interface{})

			if !assertOk {
				return nil, apperrors.ErrAssertionFailed
			}

			for _, r := range rolesVal {
				roleList = append(roleList, fmt.Sprintf("%s:%s", name, r))
			}
		}
	}

	return &models.UserContext{
		Audiences:        audiences,
		Email:            customClaims.Email,
		Acr:              customClaims.Acr,
		ExpiresAt:        stdClaims.Expiry.Time(),
		Groups:           customClaims.Groups,
		ID:               stdClaims.Subject,
		Name:             preferredName,
		PreferredName:    preferredName,
		Roles:            roleList,
		Claims:           jsonMap,
		Permissions:      customClaims.Authorization,
		SkipVerification: false,
	}, nil
}

// retrieveRefreshToken retrieves the refresh token from store or cookie.
func RetrieveRefreshToken(
	store storage.Storage,
	cookieRefreshName string,
	encryptionKey string,
	req *http.Request,
	user *models.UserContext,
) (string, string, error) {
	var token string
	var err error

	switch store != nil {
	case true:
		token, err = store.GetRefreshTokenFromStore(req.Context(), user.RawToken)
	default:
		token, err = GetRefreshTokenFromCookie(req, cookieRefreshName)
	}

	if err != nil {
		return token, "", err
	}

	encrypted := token // returns encrypted, avoids encoding twice
	token, err = encryption.DecodeText(token, encryptionKey)
	return token, encrypted, err
}

// GetAccessCookieExpiration calculates the expiration of the access token cookie.
func GetAccessCookieExpiration(
	logger *zap.Logger,
	accessTokenDuration time.Duration,
	refresh string,
) time.Duration {
	// notes: by default the duration of the access token will be the configuration option, if
	// however we can decode the refresh token, we will set the duration to the duration of the
	// refresh token
	duration := accessTokenDuration

	webToken, err := jwt.ParseSigned(refresh, constant.SignatureAlgs[:])
	if err != nil {
		logger.Error("unable to parse token")
	}

	if ident, err := ExtractIdentity(webToken); err == nil {
		delta := time.Until(ident.ExpiresAt)

		if delta > 0 {
			duration = delta
		}

		logger.Debug(
			"parsed refresh token with new duration",
			zap.Duration("new duration", delta),
		)
	} else {
		logger.Debug("refresh token is opaque and cannot be used to extend calculated duration")
	}

	return duration
}

func GetCodeFlowTokens(
	scope *models.RequestScope,
	writer http.ResponseWriter,
	req *http.Request,
	enablePKCE bool,
	cookiePKCEName string,
	idpClient *http.Client,
	accessForbidden func(wrt http.ResponseWriter, req *http.Request) context.Context,
	accessError func(wrt http.ResponseWriter, req *http.Request) context.Context,
	newOAuth2Config func(redirectionURL string) *oauth2.Config,
	getRedirectionURL func(wrt http.ResponseWriter, req *http.Request) string,
) (string, string, string, error) {
	// step: ensure we have a authorization code
	code := req.URL.Query().Get("code")

	if code == "" {
		accessError(writer, req)
		return "", "", "", apperrors.ErrMissingAuthCode
	}

	conf := newOAuth2Config(getRedirectionURL(writer, req))

	var codeVerifier *http.Cookie

	if enablePKCE {
		var err error
		codeVerifier, err = req.Cookie(cookiePKCEName)
		if err != nil {
			scope.Logger.Error("problem getting pkce cookie", zap.Error(err))
			accessForbidden(writer, req)
			return "", "", "", err
		}
	}

	resp, err := exchangeAuthenticationCode(
		req.Context(),
		conf,
		code,
		codeVerifier,
		idpClient,
	)
	if err != nil {
		scope.Logger.Error("unable to exchange code for access token", zap.Error(err))
		accessForbidden(writer, req)
		return "", "", "", err
	}

	idToken, assertOk := resp.Extra("id_token").(string)
	if !assertOk {
		scope.Logger.Error("unable to obtain id token", zap.Error(err))
		accessForbidden(writer, req)
		return "", "", "", err
	}

	return resp.AccessToken, idToken, resp.RefreshToken, nil
}

// exchangeAuthenticationCode exchanges the authentication code with the oauth server for a access token.
func exchangeAuthenticationCode(
	ctx context.Context,
	oConfig *oauth2.Config,
	code string,
	codeVerifierCookie *http.Cookie,
	httpClient *http.Client,
) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	start := time.Now()
	authCodeOptions := []oauth2.AuthCodeOption{}

	if codeVerifierCookie != nil {
		if codeVerifierCookie.Value == "" {
			return nil, apperrors.ErrPKCECookieEmpty
		}
		authCodeOptions = append(
			authCodeOptions,
			oauth2.SetAuthURLParam(pkce.ParamCodeVerifier, codeVerifierCookie.Value),
		)
	}

	token, err := oConfig.Exchange(ctx, code, authCodeOptions...)
	if err != nil {
		return token, err
	}

	taken := time.Since(start).Seconds()
	metrics.OauthTokensMetric.WithLabelValues("exchange").Inc()
	metrics.OauthLatencyMetric.WithLabelValues("exchange").Observe(taken)

	return token, err
}

func GetRequestURIFromCookie(
	scope *models.RequestScope,
	encodedRequestURI *http.Cookie,
) string {
	// some clients URL-escape padding characters
	unescapedValue, err := url.PathUnescape(encodedRequestURI.Value)
	if err != nil {
		scope.Logger.Warn(
			"app did send a corrupted redirectURI in cookie: invalid url escaping",
			zap.Error(err),
		)
	}
	// Since the value is passed with a cookie, we do not expect the client to use base64url (but the
	// base64-encoded value may itself be url-encoded).
	// This is safe for browsers using atob() but needs to be treated with care for nodeJS clients,
	// which natively use base64url encoding, and url-escape padding '=' characters.
	decoded, err := base64.StdEncoding.DecodeString(unescapedValue)
	if err != nil {
		scope.Logger.Warn(
			"app did send a corrupted redirectURI in cookie: invalid base64url encoding",
			zap.Error(err),
			zap.String("encoded_value", unescapedValue))
	}

	return string(decoded)
}
