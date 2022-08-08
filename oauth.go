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

package main

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"

	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	GrantTypeAuthCode     = "authorization_code"
	GrantTypeUserCreds    = "password"
	GrantTypeRefreshToken = "refresh_token"
	GrantTypeClientCreds  = "client_credentials"
	GrantTypeUmaTicket    = "urn:ietf:params:oauth:grant-type:uma-ticket"
)

// newOAuth2Config returns a oauth2 config
func (r *oauthProxy) newOAuth2Config(redirectionURL string) *oauth2.Config {
	defaultScope := []string{"openid"}

	conf := &oauth2.Config{
		ClientID:     r.config.ClientID,
		ClientSecret: r.config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  r.provider.Endpoint().AuthURL,
			TokenURL: r.provider.Endpoint().TokenURL,
		},
		RedirectURL: redirectionURL,
		Scopes:      append(r.config.Scopes, defaultScope...),
	}

	return conf
}

// getRefreshedToken attempts to refresh the access token, returning the parsed token, optionally with a renewed
// refresh token and the time the access and refresh tokens expire
//
// NOTE: we may be able to extract the specific (non-standard) claim refresh_expires_in and refresh_expires
// from response.RawBody.
// When not available, keycloak provides us with the same (for now) expiry value for ID token.
func getRefreshedToken(conf *oauth2.Config, proxyConfig *Config, oldRefreshToken string) (jwt.JSONWebToken, string, string, time.Time, time.Duration, error) {
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
	oauthTokensMetric.WithLabelValues("renew").Inc()
	oauthLatencyMetric.WithLabelValues("renew").Observe(taken)

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
func exchangeAuthenticationCode(client *oauth2.Config, code string, skipOpenIDProviderTLSVerify bool) (*oauth2.Token, error) {
	return getToken(client, GrantTypeAuthCode, code, skipOpenIDProviderTLSVerify)
}

// getToken retrieves a code from the provider, extracts and verified the token
func getToken(config *oauth2.Config, grantType, code string, skipOpenIDProviderTLSVerify bool) (*oauth2.Token, error) {
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
	token, err := config.Exchange(ctx, code)

	if err != nil {
		return token, err
	}

	taken := time.Since(start).Seconds()

	switch grantType {
	case GrantTypeAuthCode:
		oauthTokensMetric.WithLabelValues("exchange").Inc()
		oauthLatencyMetric.WithLabelValues("exchange").Observe(taken)
	case GrantTypeRefreshToken:
		oauthTokensMetric.WithLabelValues("renew").Inc()
		oauthLatencyMetric.WithLabelValues("renew").Observe(taken)
	}

	return token, err
}
