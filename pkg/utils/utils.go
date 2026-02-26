/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils //nolint:revive

import (
	"bytes"
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/metrics"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2"
)

//nolint:gochecknoglobals
var (
	AllHTTPMethods = []string{
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace,
	}
	symbolsFilter = regexp.MustCompilePOSIX("[_$><\\[\\].,\\+-/'%^&*()!\\\\]+")
)

func GetRequestHostURL(req *http.Request) string {
	scheme := constant.UnsecureScheme

	if req.TLS != nil {
		scheme = constant.SecureScheme
	}

	redirect := fmt.Sprintf("%s://%s",
		DefaultTo(req.Header.Get(constant.HeaderXForwardedProto), scheme),
		DefaultTo(req.Header.Get(constant.HeaderXForwardedHost), req.Host))

	return redirect
}

func DecodeKeyPairs(list []string) (map[string]string, error) {
	keyPairs := make(map[string]string)

	for _, pair := range list {
		items := strings.Split(pair, "=")

		if len(items) < 2 || items[0] == "" {
			return keyPairs, fmt.Errorf("invalid tag '%s' should be key=pair", pair)
		}

		keyPairs[items[0]] = strings.Join(items[1:], "=")
	}

	return keyPairs, nil
}

func IsValidHTTPMethod(method string) bool {
	return slices.Contains(AllHTTPMethods, method)
}

func DefaultTo(v, d string) string {
	if v != "" {
		return v
	}

	return d
}

func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}

func HasAccess(need map[string]bool, have []string, all bool) bool {
	if len(need) == 0 {
		return true
	}

	var matched int

	for _, x := range have {
		_, found := need[x]
		if found && !all {
			return true
		}

		if found {
			matched++
		}

		if matched == len(need) {
			return true
		}
	}

	return false
}

func ContainsSubString(value string, list []string) bool {
	return slices.ContainsFunc(list, func(val string) bool {
		return strings.Contains(value, val)
	})
}

// TryDialEndpoint dials the upstream endpoint via plain HTTP.
func TryDialEndpoint(location *url.URL) (net.Conn, error) {
	switch dialAddress := DialAddress(location); location.Scheme {
	case constant.UnsecureScheme:
		return net.Dial("tcp", dialAddress)
	default:
		return tls.Dial("tcp", dialAddress, &tls.Config{
			Rand: cryptorand.Reader,
			//nolint:gosec
			InsecureSkipVerify: true,
		})
	}
}

func IsUpgradedConnection(req *http.Request) bool {
	return req.Header.Get(constant.HeaderUpgrade) != ""
}

// TransferBytes transfers bytes between the sink and source.
func TransferBytes(src io.Reader, dest io.Writer, wg *sync.WaitGroup) (int64, error) {
	defer wg.Done()
	return io.Copy(dest, src)
}

// TryUpdateConnection attempt to upgrade the connection to a http pdy stream.
func TryUpdateConnection(req *http.Request, writer http.ResponseWriter, endpoint *url.URL) error {
	server, err := TryDialEndpoint(endpoint)
	if err != nil {
		return err
	}

	defer server.Close()

	hijacker, assertOk := writer.(http.Hijacker)

	if !assertOk {
		return apperrors.ErrHijackerMethodMissing
	}

	client, _, err := hijacker.Hijack()
	if err != nil {
		return err
	}

	err = req.Write(server)
	if err != nil {
		return err
	}

	headerBytes := make([]byte, constant.HTTPStatusHeaderLen)

	_, err = server.Read(headerBytes)
	if err != nil {
		return err
	}

	_, err = client.Write(headerBytes)
	if err != nil {
		return err
	}

	if !bytes.Contains(headerBytes, []byte(constant.SwitchProtoHeader)) {
		_, err = client.Write([]byte(constant.CRLF))
		if err != nil {
			return err
		}

		return apperrors.ErrConnectionUpgrade
	}

	var wGroup sync.WaitGroup

	numConnectionWorkers := 2
	wGroup.Add(numConnectionWorkers)

	go func() { _, _ = TransferBytes(server, client, &wGroup) }()
	go func() { _, _ = TransferBytes(client, server, &wGroup) }()

	wGroup.Wait()

	return nil
}

// DialAddress extracts the dial address from the url.
func DialAddress(location *url.URL) string {
	items := strings.Split(location.Host, ":")

	locationItems := 2
	if len(items) != locationItems {
		switch location.Scheme {
		case constant.UnsecureScheme:
			return location.Host + ":80"
		default:
			return location.Host + ":443"
		}
	}

	return location.Host
}

func ToHeader(v string) string {
	symbols := symbolsFilter.Split(v, -1)
	list := make([]string, 0, len(symbols))

	// step: filter out any symbols and convert to dashes
	for _, x := range symbols {
		list = append(list, Capitalize(x))
	}

	return strings.Join(list, "-")
}

// Capitalize capitalizes the first letter of a word.
func Capitalize(word string) string {
	if word == "" {
		return ""
	}

	r, n := utf8.DecodeRuneInString(word)

	return string(unicode.ToUpper(r)) + word[n:]
}

// MergeMaps simples copies the keys from source to destination.
func MergeMaps(dest, source map[string]string) map[string]string {
	maps.Copy(dest, source)
	return dest
}

// GetWithin calculates a duration of x percent of the time period, i.e. something
// expires in 1 hours, get me a duration within 80%.
func GetWithin(expires time.Time, within float64) time.Duration {
	left := expires.UTC().Sub(time.Now().UTC()).Seconds()

	if left <= 0 {
		return time.Duration(0)
	}

	seconds := int(left * within)

	return time.Duration(seconds) * time.Second
}

// PrintError display the command line usage and error.
func PrintError(message string, args ...any) cli.ExitCoder {
	return cli.Exit(fmt.Sprintf("[error] "+message, args...), 1)
}

// RealIP retrieves the client ip address from a http request.
func RealIP(req *http.Request) string {
	rAddr := req.RemoteAddr

	if ip := req.Header.Get(constant.HeaderXForwardedFor); ip != "" {
		rAddr = strings.Split(ip, ", ")[0]
	} else if ip := req.Header.Get(constant.HeaderXRealIP); ip != "" {
		rAddr = ip
	} else {
		rAddr, _, _ = net.SplitHostPort(rAddr)
	}

	return rAddr
}

func GenerateHmac(req *http.Request, encKey string) (string, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return "", err
	}

	stringToSign := fmt.Sprintf(
		"%s\n%s%s\n%s;%s;%s",
		req.Method,
		req.URL.Path,
		req.URL.RawQuery,
		req.Header.Get(constant.AuthorizationHeader),
		req.Host,
		sha256.Sum256(body),
	)

	mac := hmac.New(sha256.New, []byte(encKey))
	mac.Write([]byte(stringToSign))
	reqHmac := mac.Sum(nil)
	hexHmac := hex.EncodeToString(reqHmac)

	return hexHmac, nil
}

// WithOAuthURI returns the oauth uri.
func WithOAuthURI(baseURI string, oauthURI string) func(uri string) string {
	return func(uri string) string {
		uri = strings.TrimPrefix(uri, "/")
		if baseURI != "" {
			oauthURI = strings.TrimPrefix(oauthURI, "/")
			return fmt.Sprintf("%s/%s/%s", baseURI, oauthURI, uri)
		}

		return fmt.Sprintf("%s/%s", oauthURI, uri)
	}
}

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
	case []any:
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
	var (
		oIDToken  *oidc3.IDToken
		oAccToken *oidc3.IDToken
		err       error
	)

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

type LimitedBufferPool struct {
	pool  *sync.Pool
	limit int32
	count int32
}

func NewLimitedBufferPool(limit int32) *LimitedBufferPool {
	return &LimitedBufferPool{
		pool: &sync.Pool{
			New: func() any {
				return &bytes.Buffer{}
			},
		},
		limit: limit,
		count: 0,
	}
}

func (limPool *LimitedBufferPool) Get() (*bytes.Buffer, error) {
	curr := atomic.LoadInt32(&limPool.count)
	if curr > 0 {
		atomic.AddInt32(&limPool.count, int32(-1))
	}

	val, ok := limPool.pool.Get().(*bytes.Buffer)
	if !ok {
		return nil, errors.New("assertion to *bytes.Buffer failed")
	}

	return val, nil
}

func (limPool *LimitedBufferPool) Put(buf *bytes.Buffer) {
	curr := atomic.LoadInt32(&limPool.count)
	if curr <= limPool.limit {
		atomic.AddInt32(&limPool.count, int32(1))

		buf.Reset()
		limPool.pool.Put(buf)
	}
}

func (limPool *LimitedBufferPool) Capacity() int32 {
	return atomic.LoadInt32(&limPool.count)
}
