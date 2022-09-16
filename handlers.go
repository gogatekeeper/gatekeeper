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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"

	"net/http"
	"net/http/pprof"
	"net/url"
	"path"
	"strings"
	"time"

	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type DiscoveryResponse struct {
	ExpiredURL string `json:"expired_endpoint"`
	LogoutURL  string `json:"logout_endpoint"`
	TokenURL   string `json:"token_endpoint"`
	LoginURL   string `json:"login_endpoint"`
}

// getRedirectionURL returns the redirectionURL for the oauth flow
func (r *oauthProxy) getRedirectionURL(wrt http.ResponseWriter, req *http.Request) string {
	var redirect string

	switch r.config.RedirectionURL {
	case "":
		// need to determine the scheme, cx.Request.URL.Scheme doesn't have it, best way is to default
		// and then check for TLS
		scheme := constant.UnsecureScheme
		if req.TLS != nil {
			scheme = constant.SecureScheme
		}

		// @QUESTION: should I use the X-Forwarded-<header>?? ..
		redirect = fmt.Sprintf("%s://%s",
			utils.DefaultTo(req.Header.Get("X-Forwarded-Proto"), scheme),
			utils.DefaultTo(req.Header.Get("X-Forwarded-Host"), req.Host))
	default:
		redirect = r.config.RedirectionURL
	}

	state, _ := req.Cookie(r.config.CookieOAuthStateName)

	if state != nil && req.URL.Query().Get("state") != state.Value {
		r.log.Error("state parameter mismatch")
		wrt.WriteHeader(http.StatusForbidden)
		return ""
	}

	return fmt.Sprintf("%s%s", redirect, r.config.WithOAuthURI("callback"))
}

// oauthAuthorizationHandler is responsible for performing the redirection to oauth provider
func (r *oauthProxy) oauthAuthorizationHandler(wrt http.ResponseWriter, req *http.Request) {
	if r.config.SkipTokenVerification {
		wrt.WriteHeader(http.StatusNotAcceptable)
		return
	}

	scope, assertOk := req.Context().Value(constant.ContextScopeName).(*RequestScope)

	if !assertOk {
		r.log.Error(
			"assertion failed",
		)
		return
	}

	conf := r.newOAuth2Config(r.getRedirectionURL(wrt, req))
	// step: set the access type of the session
	accessType := oauth2.AccessTypeOnline

	if utils.ContainedIn("offline", r.config.Scopes) {
		accessType = oauth2.AccessTypeOffline
	}

	authURL := conf.AuthCodeURL(req.URL.Query().Get("state"), accessType)
	clientIP := utils.RealIP(req)

	scope.Logger.Debug(
		"incoming authorization request from client address",
		zap.Any("access_type", accessType),
		zap.String("auth_url", authURL),
		zap.String("client_ip", clientIP),
		zap.String("remote_addr", req.RemoteAddr),
	)

	// step: if we have a custom sign in page, lets display that
	if r.config.hasCustomSignInPage() {
		model := make(map[string]string)
		model["redirect"] = authURL

		wrt.WriteHeader(http.StatusOK)
		_ = r.Render(
			wrt,
			path.Base(r.config.SignInPage),
			utils.MergeMaps(model, r.config.Tags),
		)
		return
	}

	r.redirectToURL(authURL, wrt, req, http.StatusSeeOther)
}

/*
	oauthCallbackHandler is responsible for handling the response from oauth service
*/
//nolint:funlen,cyclop
func (r *oauthProxy) oauthCallbackHandler(writer http.ResponseWriter, req *http.Request) {
	if r.config.SkipTokenVerification {
		writer.WriteHeader(http.StatusNotAcceptable)
		return
	}

	scope, assertOk := req.Context().Value(constant.ContextScopeName).(*RequestScope)

	if !assertOk {
		r.log.Error(
			"assertion failed",
		)
		return
	}

	// step: ensure we have a authorization code
	code := req.URL.Query().Get("code")

	if code == "" {
		r.accessError(writer, req)
		return
	}

	conf := r.newOAuth2Config(r.getRedirectionURL(writer, req))

	//nolint:contextcheck
	resp, err := exchangeAuthenticationCode(
		conf,
		code,
		r.config.SkipOpenIDProviderTLSVerify,
	)

	if err != nil {
		scope.Logger.Error("unable to exchange code for access token", zap.Error(err))
		r.accessForbidden(writer, req)
		return
	}

	var rawToken string
	// Flow: once we exchange the authorization code we parse the ID Token; we then check for an access token,
	// if an access token is present and we can decode it, we use that as the session token, otherwise we default
	// to the ID Token.
	rawIDToken, assertOk := resp.Extra("id_token").(string)

	if !assertOk {
		scope.Logger.Error("unable to obtain id token", zap.Error(err))
		r.accessForbidden(writer, req)
		return
	}

	rawToken = rawIDToken

	verifier := r.provider.Verifier(&oidc3.Config{ClientID: r.config.ClientID})

	var idToken *oidc3.IDToken

	ctx, cancel := context.WithTimeout(
		context.Background(),
		r.config.OpenIDProviderTimeout,
	)

	defer cancel()

	//nolint:contextcheck
	idToken, err = verifier.Verify(ctx, rawIDToken)

	if err != nil {
		scope.Logger.Error("unable to verify the id token", zap.Error(err))
		r.accessForbidden(writer, req)
		return
	}

	token, err := jwt.ParseSigned(rawIDToken)

	if err != nil {
		scope.Logger.Error("unable to parse id token", zap.Error(err))
		r.accessForbidden(writer, req)
		return
	}

	stdClaims := &jwt.Claims{}
	// Extract custom claims
	var customClaims struct {
		Email string `json:"email"`
	}

	err = token.UnsafeClaimsWithoutVerification(stdClaims, &customClaims)

	if err != nil {
		scope.Logger.Error("unable to parse id token for claims", zap.Error(err))
		r.accessForbidden(writer, req)
		return
	}

	// check https://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken - at_hash
	// keycloak seems doesnt support yet at_hash
	// https://stackoverflow.com/questions/60818373/configure-keycloak-to-include-an-at-hash-claim-in-the-id-token
	if idToken.AccessTokenHash != "" {
		err = idToken.VerifyAccessToken(resp.AccessToken)

		if err != nil {
			scope.Logger.Error("unable to verify access token", zap.Error(err))
			r.accessForbidden(writer, req)
			return
		}
	}

	accToken, err := jwt.ParseSigned(resp.AccessToken)

	if err == nil {
		token = accToken
		rawToken = resp.AccessToken
	} else {
		scope.Logger.Warn(
			"unable to parse the access token, using id token only",
			zap.Error(err),
		)
	}

	stdClaims = &jwt.Claims{}

	err = token.UnsafeClaimsWithoutVerification(stdClaims, &customClaims)

	if err != nil {
		scope.Logger.Error("unable to parse access token for claims", zap.Error(err))
		r.accessForbidden(writer, req)
		return
	}

	accessToken := rawToken

	// step: are we encrypting the access token?
	if r.config.EnableEncryptedToken || r.config.ForceEncryptedCookie {
		if accessToken, err = encryption.EncodeText(accessToken, r.config.EncryptionKey); err != nil {
			scope.Logger.Error("unable to encode the access token", zap.Error(err))
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	scope.Logger.Debug(
		"issuing access token for user",
		zap.String("access token", accessToken),
		zap.String("email", customClaims.Email),
		zap.String("sub", stdClaims.Subject),
		zap.String("expires", stdClaims.Expiry.Time().Format(time.RFC3339)),
		zap.String("duration", time.Until(stdClaims.Expiry.Time()).String()),
	)

	scope.Logger.Info(
		"issuing access token for user",
		zap.String("email", customClaims.Email),
		zap.String("sub", stdClaims.Subject),
		zap.String("expires", stdClaims.Expiry.Time().Format(time.RFC3339)),
		zap.String("duration", time.Until(stdClaims.Expiry.Time()).String()),
	)

	// @metric a token has been issued
	oauthTokensMetric.WithLabelValues("issued").Inc()

	// step: does the response have a refresh token and we do NOT ignore refresh tokens?
	if r.config.EnableRefreshTokens && resp.RefreshToken != "" {
		var encrypted string
		encrypted, err = encryption.EncodeText(resp.RefreshToken, r.config.EncryptionKey)

		if err != nil {
			scope.Logger.Error(
				"failed to encrypt the refresh token",
				zap.Error(err),
				zap.String("sub", stdClaims.Subject),
				zap.String("email", customClaims.Email),
			)

			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		// drop in the access token - cookie expiration = access token
		r.dropAccessTokenCookie(
			req,
			writer,
			accessToken,
			r.getAccessCookieExpiration(resp.RefreshToken),
		)

		var expiration time.Duration
		// notes: not all idp refresh tokens are readable, google for example, so we attempt to decode into
		// a jwt and if possible extract the expiration, else we default to 10 days

		refreshToken, err := jwt.ParseSigned(resp.RefreshToken)

		if err != nil {
			scope.Logger.Error(
				"failed to parse refresh token",
				zap.Error(err),
				zap.String("sub", stdClaims.Subject),
				zap.String("email", customClaims.Email),
			)

			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		stdRefreshClaims := &jwt.Claims{}

		err = refreshToken.UnsafeClaimsWithoutVerification(stdRefreshClaims)

		if err != nil {
			expiration = 0
		} else {
			expiration = time.Until(stdRefreshClaims.Expiry.Time())
		}

		switch r.useStore() {
		case true:
			if err = r.StoreRefreshToken(rawToken, encrypted, expiration); err != nil {
				scope.Logger.Warn(
					"failed to save the refresh token in the store",
					zap.Error(err),
					zap.String("sub", stdClaims.Subject),
					zap.String("email", customClaims.Email),
				)
			}
		default:
			r.dropRefreshTokenCookie(req, writer, encrypted, expiration)
		}
	} else {
		r.dropAccessTokenCookie(
			req,
			writer,
			accessToken,
			time.Until(stdClaims.Expiry.Time()),
		)
	}

	// step: decode the request variable
	redirectURI := "/"

	if req.URL.Query().Get("state") != "" {
		if encodedRequestURI, _ := req.Cookie(r.config.CookieRequestURIName); encodedRequestURI != nil {
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

			redirectURI = string(decoded)
		}
	}

	scope.Logger.Debug("redirecting to", zap.String("location", redirectURI))
	r.redirectToURL(redirectURI, writer, req, http.StatusSeeOther)
}

/*
	loginHandler provide's a generic endpoint for clients to perform a user_credentials login to the provider
*/
//nolint:funlen,cyclop // refactor
func (r *oauthProxy) loginHandler(writer http.ResponseWriter, req *http.Request) {
	scope, assertOk := req.Context().Value(constant.ContextScopeName).(*RequestScope)

	if !assertOk {
		r.log.Error(
			"assertion failed",
		)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	errorMsg, code, err := func() (string, int, error) {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			r.config.OpenIDProviderTimeout,
		)

		if r.config.SkipOpenIDProviderTLSVerify {
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			sslcli := &http.Client{Transport: tr}
			ctx = context.WithValue(ctx, oauth2.HTTPClient, sslcli)
		}

		defer cancel()

		if !r.config.EnableLoginHandler {
			return "attempt to login when login handler is disabled",
				http.StatusNotImplemented,
				errors.New("login handler disabled")
		}

		username := req.PostFormValue("username")
		password := req.PostFormValue("password")

		if username == "" || password == "" {
			return "request does not have both username and password",
				http.StatusBadRequest,
				errors.New("no credentials")
		}

		conf := r.newOAuth2Config(r.getRedirectionURL(writer, req))

		start := time.Now()
		token, err := conf.PasswordCredentialsToken(ctx, username, password)

		if err != nil {
			if !token.Valid() {
				return "invalid user credentials provided", http.StatusUnauthorized, err
			}

			return "unable to request the access token via grant_type 'password'",
				http.StatusInternalServerError,
				err
		}

		// @metric observe the time taken for a login request
		oauthLatencyMetric.WithLabelValues("login").Observe(time.Since(start).Seconds())

		accessToken := token.AccessToken
		refreshToken := token.RefreshToken
		webToken, err := jwt.ParseSigned(token.AccessToken)

		if err != nil {
			return "unable to decode the access token", http.StatusNotImplemented, err
		}

		identity, err := extractIdentity(webToken)

		if err != nil {
			return "unable to extract identity from access token",
				http.StatusNotImplemented,
				err
		}

		writer.Header().Set("Content-Type", "application/json")
		idToken, assertOk := token.Extra("id_token").(string)

		if !assertOk {
			return "",
				http.StatusInternalServerError,
				fmt.Errorf("token response does not contain an id_token")
		}

		expiresIn, assertOk := token.Extra("expires_in").(float64)

		if !assertOk {
			return "",
				http.StatusInternalServerError,
				fmt.Errorf("token response does not contain expires_in")
		}

		// step: are we encrypting the access token?
		var plainIDToken string

		if r.config.EnableEncryptedToken || r.config.ForceEncryptedCookie {
			if accessToken, err = encryption.EncodeText(accessToken, r.config.EncryptionKey); err != nil {
				scope.Logger.Error("unable to encode the access token", zap.Error(err))
				return "unable to encode the access token",
					http.StatusInternalServerError,
					err
			}

			if refreshToken, err = encryption.EncodeText(refreshToken, r.config.EncryptionKey); err != nil {
				scope.Logger.Error("unable to encode the refresh token", zap.Error(err))
				return "unable to encode the refresh token",
					http.StatusInternalServerError,
					err
			}

			plainIDToken = idToken

			if idToken, err = encryption.EncodeText(idToken, r.config.EncryptionKey); err != nil {
				scope.Logger.Error("unable to encode the idToken token", zap.Error(err))
				return "unable to encode the idToken token",
					http.StatusInternalServerError,
					err
			}
		}

		// step: does the response have a refresh token and we do NOT ignore refresh tokens?
		if r.config.EnableRefreshTokens && token.RefreshToken != "" {
			var encrypted string
			encrypted, err = encryption.EncodeText(token.RefreshToken, r.config.EncryptionKey)

			if err != nil {
				scope.Logger.Error("failed to encrypt the refresh token", zap.Error(err))
				return "failed to encrypt the refresh token",
					http.StatusInternalServerError,
					err
			}

			// drop in the access token - cookie expiration = access token
			r.dropAccessTokenCookie(
				req,
				writer,
				accessToken,
				r.getAccessCookieExpiration(token.RefreshToken),
			)

			var expiration time.Duration
			// notes: not all idp refresh tokens are readable, google for example, so we attempt to decode into
			// a jwt and if possible extract the expiration, else we default to 10 days
			refreshToken, errRef := jwt.ParseSigned(token.RefreshToken)

			if errRef != nil {
				scope.Logger.Error("failed to parse refresh token", zap.Error(errRef))
				return "failed to parse refresh token",
					http.StatusInternalServerError,
					errRef
			}

			stdRefreshClaims := &jwt.Claims{}

			err = refreshToken.UnsafeClaimsWithoutVerification(stdRefreshClaims)

			if err != nil {
				expiration = 0
			} else {
				expiration = time.Until(stdRefreshClaims.Expiry.Time())
			}

			switch r.useStore() {
			case true:
				if err = r.StoreRefreshToken(token.AccessToken, encrypted, expiration); err != nil {
					scope.Logger.Warn(
						"failed to save the refresh token in the store",
						zap.Error(err),
					)
				}
			default:
				r.dropRefreshTokenCookie(req, writer, encrypted, expiration)
			}
		} else {
			r.dropAccessTokenCookie(
				req,
				writer,
				accessToken,
				time.Until(identity.expiresAt),
			)
		}

		// @metric a token has been issued
		oauthTokensMetric.WithLabelValues("login").Inc()
		tokenScope := token.Extra("scope")
		var tScope string

		if tokenScope != nil {
			tScope, assertOk = tokenScope.(string)

			if !assertOk {
				return "",
					http.StatusInternalServerError,
					fmt.Errorf("assertion failed")
			}
		}

		var resp tokenResponse

		if r.config.EnableEncryptedToken {
			resp = tokenResponse{
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				ExpiresIn:    expiresIn,
				Scope:        tScope,
			}
		} else {
			resp = tokenResponse{
				IDToken:      plainIDToken,
				AccessToken:  token.AccessToken,
				RefreshToken: token.RefreshToken,
				ExpiresIn:    expiresIn,
				Scope:        tScope,
			}
		}

		err = json.NewEncoder(writer).Encode(resp)

		if err != nil {
			return "", http.StatusInternalServerError, err
		}

		return "", http.StatusOK, nil
	}()

	if err != nil {
		clientIP := utils.RealIP(req)
		scope.Logger.Error(errorMsg,
			zap.String("client_ip", clientIP),
			zap.String("remote_addr", req.RemoteAddr),
			zap.Error(err))

		writer.WriteHeader(code)
	}
}

// emptyHandler is responsible for doing nothing
func emptyHandler(w http.ResponseWriter, req *http.Request) {}

/*
	logoutHandler performs a logout
	- if it's just a access token, the cookie is deleted
	- if the user has a refresh token, the token is invalidated by the provider
	- optionally, the user can be redirected by to a url
*/
//nolint:cyclop
func (r *oauthProxy) logoutHandler(writer http.ResponseWriter, req *http.Request) {
	// @check if the redirection is there
	var redirectURL string
	for k := range req.URL.Query() {
		if k == "redirect" {
			redirectURL = req.URL.Query().Get("redirect")

			if redirectURL == "" {
				// then we can default to redirection url
				redirectURL = strings.TrimSuffix(
					r.config.RedirectionURL,
					"/oauth/callback",
				)
			}
		}
	}

	scope, assertOk := req.Context().Value(constant.ContextScopeName).(*RequestScope)

	if !assertOk {
		r.log.Error(
			"assertion failed",
		)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	// @step: drop the access token
	user, err := r.getIdentity(req)

	if err != nil {
		r.accessError(writer, req)
		return
	}

	// step: can either use the id token or the refresh token
	identityToken := user.rawToken

	//nolint:vetshadow
	if refresh, _, err := r.retrieveRefreshToken(req, user); err == nil {
		identityToken = refresh
	}
	r.clearAllCookies(req, writer)

	// @metric increment the logout counter
	oauthTokensMetric.WithLabelValues("logout").Inc()

	// step: check if the user has a state session and if so revoke it
	if r.useStore() {
		go func() {
			if err = r.DeleteRefreshToken(user.rawToken); err != nil {
				scope.Logger.Error(
					"unable to remove the refresh token from store",
					zap.Error(err),
				)
			}
		}()
	}

	// @check if we should redirect to the provider
	if r.config.EnableLogoutRedirect {
		sendTo := fmt.Sprintf(
			"%s/protocol/openid-connect/logout",
			strings.TrimSuffix(
				r.config.DiscoveryURL,
				"/.well-known/openid-configuration",
			),
		)

		// @step: if no redirect uri is set
		if redirectURL == "" {
			// @step: we first check for a redirection-url and then host header
			if r.config.RedirectionURL != "" {
				redirectURL = r.config.RedirectionURL
			} else {
				redirectURL = utils.GetRequestHostURL(req)
			}
		}

		r.redirectToURL(
			fmt.Sprintf(
				"%s?redirect_uri=%s",
				sendTo,
				url.QueryEscape(redirectURL),
			),
			writer,
			req,
			http.StatusSeeOther,
		)

		return
	}

	// set the default revocation url
	revokeDefault := fmt.Sprintf(
		"%s/protocol/openid-connect/revoke",
		strings.TrimSuffix(
			r.config.DiscoveryURL,
			"/.well-known/openid-configuration",
		),
	)

	revocationURL := utils.DefaultTo(r.config.RevocationEndpoint, revokeDefault)

	// step: do we have a revocation endpoint?
	if revocationURL != "" {
		client := &http.Client{
			Timeout: r.config.OpenIDProviderTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: r.config.SkipOpenIDProviderTLSVerify,
				},
			},
		}

		if err != nil {
			scope.Logger.Error("unable to retrieve the openid client", zap.Error(err))
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		// step: add the authentication headers
		encodedID := url.QueryEscape(r.config.ClientID)
		encodedSecret := url.QueryEscape(r.config.ClientSecret)

		// step: construct the url for revocation
		request, err := http.NewRequest(
			http.MethodPost,
			revocationURL,
			bytes.NewBufferString(
				fmt.Sprintf("token=%s", identityToken),
			),
		)

		if err != nil {
			scope.Logger.Error("unable to construct the revocation request", zap.Error(err))
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		// step: add the authentication headers and content-type
		request.SetBasicAuth(encodedID, encodedSecret)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		start := time.Now()
		response, err := client.Do(request)

		if err != nil {
			scope.Logger.Error("unable to post to revocation endpoint", zap.Error(err))
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		defer response.Body.Close()

		oauthLatencyMetric.WithLabelValues("revocation").
			Observe(time.Since(start).Seconds())

		// step: check the response
		switch response.StatusCode {
		case http.StatusOK:
			scope.Logger.Info(
				"successfully logged out of the endpoint",
				zap.String("email", user.email),
			)
		default:
			content, _ := ioutil.ReadAll(response.Body)

			scope.Logger.Error(
				"invalid response from revocation endpoint",
				zap.Int("status", response.StatusCode),
				zap.String("response", string(content)),
			)

			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	// step: should we redirect the user
	if redirectURL != "" {
		r.redirectToURL(redirectURL, writer, req, http.StatusSeeOther)
	}
}

// expirationHandler checks if the token has expired
func (r *oauthProxy) expirationHandler(wrt http.ResponseWriter, req *http.Request) {
	user, err := r.getIdentity(req)

	if err != nil {
		wrt.WriteHeader(http.StatusUnauthorized)
		return
	}

	if user.isExpired() {
		wrt.WriteHeader(http.StatusUnauthorized)
		return
	}

	wrt.WriteHeader(http.StatusOK)
}

// tokenHandler display access token to screen
func (r *oauthProxy) tokenHandler(wrt http.ResponseWriter, req *http.Request) {
	user, err := r.getIdentity(req)

	if err != nil {
		r.accessError(wrt, req)
		return
	}

	token, err := jwt.ParseSigned(user.rawToken)

	if err != nil {
		r.accessError(wrt, req)
		return
	}

	jsonMap := make(map[string]interface{})
	err = token.UnsafeClaimsWithoutVerification(&jsonMap)

	if err != nil {
		r.accessError(wrt, req)
		return
	}

	result, err := json.Marshal(jsonMap)

	if err != nil {
		r.accessError(wrt, req)
		return
	}

	wrt.Header().Set("Content-Type", "application/json")

	_, _ = wrt.Write(result)
}

// healthHandler is a health check handler for the service
func (r *oauthProxy) healthHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set(constant.VersionHeader, getVersion())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK\n"))
}

// debugHandler is responsible for providing the pprof
//
//nolint:cyclop
func (r *oauthProxy) debugHandler(writer http.ResponseWriter, req *http.Request) {
	const symbolProfile = "symbol"
	//nolint:contextcheck
	name := chi.URLParam(req, "name")

	switch req.Method {
	case http.MethodGet:
		switch name {
		case "heap":
			fallthrough
		case "goroutine":
			fallthrough
		case "block":
			fallthrough
		case "threadcreate":
			pprof.Handler(name).ServeHTTP(writer, req)
		case "cmdline":
			pprof.Cmdline(writer, req)
		case "profile":
			pprof.Profile(writer, req)
		case "trace":
			pprof.Trace(writer, req)
		case symbolProfile:
			pprof.Symbol(writer, req)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	case http.MethodPost:
		switch name {
		case symbolProfile:
			pprof.Symbol(writer, req)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}
}

// proxyMetricsHandler forwards the request into the prometheus handler
func (r *oauthProxy) proxyMetricsHandler(wrt http.ResponseWriter, req *http.Request) {
	if r.config.LocalhostMetrics {
		if !net.ParseIP(utils.RealIP(req)).IsLoopback() {
			r.accessForbidden(wrt, req)
			return
		}
	}
	r.metricsHandler.ServeHTTP(wrt, req)
}

// retrieveRefreshToken retrieves the refresh token from store or cookie
func (r *oauthProxy) retrieveRefreshToken(req *http.Request, user *userContext) (string, string, error) {
	var token string
	var err error

	switch r.useStore() {
	case true:
		token, err = r.GetRefreshToken(user.rawToken)
	default:
		token, err = utils.GetRefreshTokenFromCookie(req, r.config.CookieRefreshName)
	}

	if err != nil {
		return token, "", err
	}

	encrypted := token // returns encrypted, avoids encoding twice
	token, err = encryption.DecodeText(token, r.config.EncryptionKey)
	return token, encrypted, err
}

func methodNotAllowHandlder(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = w.Write(nil)
}

// discoveryHandler provides endpoint info
func (r *oauthProxy) discoveryHandler(wrt http.ResponseWriter, req *http.Request) {
	resp := &DiscoveryResponse{
		ExpiredURL: r.config.WithOAuthURI(strings.TrimPrefix(constant.ExpiredURL, "/")),
		LogoutURL:  r.config.WithOAuthURI(strings.TrimPrefix(constant.LogoutURL, "/")),
		TokenURL:   r.config.WithOAuthURI(strings.TrimPrefix(constant.TokenURL, "/")),
		LoginURL:   r.config.WithOAuthURI(strings.TrimPrefix(constant.LoginURL, "/")),
	}

	respBody, err := json.Marshal(resp)

	if err != nil {
		r.log.Error(
			"problem marshalling response",
			zap.String("error", err.Error()),
		)

		wrt.WriteHeader(http.StatusInternalServerError)
		return
	}

	wrt.Header().Set("Content-Type", "application/json")
	wrt.WriteHeader(http.StatusOK)
	_, err = wrt.Write(respBody)

	if err != nil {
		r.log.Error(
			"problem during response write",
			zap.String("error", err.Error()),
		)
	}
}
