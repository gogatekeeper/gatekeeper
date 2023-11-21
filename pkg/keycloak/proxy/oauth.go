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

package proxy

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/config/core"
	"github.com/gogatekeeper/gatekeeper/pkg/keycloak/config"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/metrics"
	"github.com/grokify/go-pkce"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"

	"github.com/go-jose/go-jose/v3/jwt"
)

// newOAuth2Config returns a oauth2 config
func newOAuth2Config(
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

// getRefreshedToken attempts to refresh the access token, returning the parsed token, optionally with a renewed
// refresh token and the time the access and refresh tokens expire
//
// NOTE: we may be able to extract the specific (non-standard) claim refresh_expires_in and refresh_expires
// from response.RawBody.
// When not available, keycloak provides us with the same (for now) expiry value for ID token.
func getRefreshedToken(conf *oauth2.Config, proxyConfig *config.Config, oldRefreshToken string) (jwt.JSONWebToken, string, string, time.Time, time.Duration, error) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		proxyConfig.OpenIDProviderTimeout,
	)

	if proxyConfig.SkipOpenIDProviderTLSVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		sslcli := &http.Client{Transport: tr}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, sslcli)
	}

	defer cancel()

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

	token, err := jwt.ParseSigned(tkn.AccessToken)

	if err != nil {
		return jwt.JSONWebToken{},
			"",
			"",
			time.Time{},
			time.Duration(0),
			err
	}

	refreshToken, err := jwt.ParseSigned(tkn.RefreshToken)

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

// exchangeAuthenticationCode exchanges the authentication code with the oauth server for a access token
func exchangeAuthenticationCode(
	client *oauth2.Config,
	code string,
	codeVerifierCookie *http.Cookie,
	skipOpenIDProviderTLSVerify bool,
) (*oauth2.Token, error) {
	return getToken(
		client,
		core.GrantTypeAuthCode,
		code,
		codeVerifierCookie,
		skipOpenIDProviderTLSVerify,
	)
}

// getToken retrieves a code from the provider
func getToken(
	oConfig *oauth2.Config,
	grantType,
	code string,
	codeVerifierCookie *http.Cookie,
	skipOpenIDProviderTLSVerify bool,
) (*oauth2.Token, error) {
	ctx := context.Background()

	if skipOpenIDProviderTLSVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		sslcli := &http.Client{Transport: tr}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, sslcli)
	} else {
		ctx = context.Background()
	}

	start := time.Now()
	authCodeOptions := []oauth2.AuthCodeOption{}

	if grantType == core.GrantTypeAuthCode {
		if codeVerifierCookie != nil {
			if codeVerifierCookie.Value == "" {
				return nil, apperrors.ErrPKCECookieEmpty
			}
			authCodeOptions = append(
				authCodeOptions,
				oauth2.SetAuthURLParam(pkce.ParamCodeVerifier, codeVerifierCookie.Value),
			)
		}
	}

	token, err := oConfig.Exchange(ctx, code, authCodeOptions...)

	if err != nil {
		return token, err
	}

	taken := time.Since(start).Seconds()

	switch grantType {
	case core.GrantTypeAuthCode:
		metrics.OauthTokensMetric.WithLabelValues("exchange").Inc()
		metrics.OauthLatencyMetric.WithLabelValues("exchange").Observe(taken)
	case core.GrantTypeRefreshToken:
		metrics.OauthTokensMetric.WithLabelValues("renew").Inc()
		metrics.OauthLatencyMetric.WithLabelValues("renew").Observe(taken)
	}

	return token, err
}
