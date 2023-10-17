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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"github.com/grokify/go-pkce"
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
func (r *OauthProxy) getRedirectionURL(wrt http.ResponseWriter, req *http.Request) string {
	var redirect string

	switch r.Config.RedirectionURL {
	case "":
		var scheme string
		var host string

		if r.Config.NoProxy && !r.Config.NoRedirects {
			scheme = req.Header.Get("X-Forwarded-Proto")
			host = req.Header.Get("X-Forwarded-Host")
		} else {
			// need to determine the scheme, cx.Request.URL.Scheme doesn't have it, best way is to default
			// and then check for TLS
			scheme = constant.UnsecureScheme
			host = req.Host
			if req.TLS != nil {
				scheme = constant.SecureScheme
			}
		}

		if scheme == constant.UnsecureScheme && r.Config.SecureCookie {
			hint := "you have secure cookie set to true but using http "
			hint += "use https or secure cookie false"
			r.Log.Warn(hint)
		}

		redirect = fmt.Sprintf("%s://%s", scheme, host)
	default:
		redirect = r.Config.RedirectionURL
	}

	state, _ := req.Cookie(r.Config.CookieOAuthStateName)

	if state != nil && req.URL.Query().Get("state") != state.Value {
		r.Log.Error("state parameter mismatch")
		wrt.WriteHeader(http.StatusForbidden)
		return ""
	}

	return fmt.Sprintf("%s%s", redirect, r.Config.WithOAuthURI(constant.CallbackURL))
}

// oauthAuthorizationHandler is responsible for performing the redirection to oauth provider
func (r *OauthProxy) oauthAuthorizationHandler(wrt http.ResponseWriter, req *http.Request) {
	if r.Config.SkipTokenVerification {
		wrt.WriteHeader(http.StatusNotAcceptable)
		return
	}

	scope, assertOk := req.Context().Value(constant.ContextScopeName).(*RequestScope)

	if !assertOk {
		r.Log.Error(
			"assertion failed",
		)
		return
	}

	scope.Logger.Debug("authorization handler")

	conf := r.newOAuth2Config(r.getRedirectionURL(wrt, req))
	// step: set the access type of the session
	accessType := oauth2.AccessTypeOnline

	if utils.ContainedIn("offline", r.Config.Scopes) {
		accessType = oauth2.AccessTypeOffline
	}

	authCodeOptions := []oauth2.AuthCodeOption{
		accessType,
	}

	if r.Config.EnablePKCE {
		codeVerifier, err := pkce.NewCodeVerifierWithLength(96)

		if err != nil {
			r.Log.Error(
				apperrors.ErrPKCECodeCreation.Error(),
			)
			return
		}

		codeChallenge := pkce.CodeChallengeS256(codeVerifier)
		authCodeOptions = append(
			authCodeOptions,
			oauth2.SetAuthURLParam(pkce.ParamCodeChallenge, codeChallenge),
			oauth2.SetAuthURLParam(pkce.ParamCodeChallengeMethod, pkce.MethodS256),
		)
		r.writePKCECookie(wrt, codeVerifier)
	}

	authURL := conf.AuthCodeURL(
		req.URL.Query().Get("state"),
		authCodeOptions...,
	)

	clientIP := utils.RealIP(req)

	scope.Logger.Debug(
		"incoming authorization request from client address",
		zap.Any("access_type", accessType),
		zap.String("client_ip", clientIP),
		zap.String("remote_addr", req.RemoteAddr),
	)

	// step: if we have a custom sign in page, lets display that
	if r.Config.HasCustomSignInPage() {
		model := make(map[string]string)
		model["redirect"] = authURL

		wrt.WriteHeader(http.StatusOK)
		_ = r.Render(
			wrt,
			path.Base(r.Config.SignInPage),
			utils.MergeMaps(model, r.Config.Tags),
		)
		return
	}

	scope.Logger.Debug("redirecting to auth_url", zap.String("auth_url", authURL))
	r.redirectToURL(authURL, wrt, req, http.StatusSeeOther)
}

/*
	oauthCallbackHandler is responsible for handling the response from oauth service
*/
//nolint:cyclop
func (r *OauthProxy) oauthCallbackHandler(writer http.ResponseWriter, req *http.Request) {
	if r.Config.SkipTokenVerification {
		writer.WriteHeader(http.StatusNotAcceptable)
		return
	}

	scope, assertOk := req.Context().Value(constant.ContextScopeName).(*RequestScope)
	if !assertOk {
		r.Log.Error("assertion failed")
		return
	}

	scope.Logger.Debug("callback handler")
	//nolint:contextcheck
	accessToken, identityToken, refreshToken, err := r.getCodeFlowTokens(scope, writer, req)
	if err != nil {
		return
	}

	rawAccessToken := accessToken

	//nolint:contextcheck
	stdClaims, customClaims, err := r.verifyOIDCTokens(scope, accessToken, identityToken, writer, req)
	if err != nil {
		return
	}

	// @metric a token has been issued
	oauthTokensMetric.WithLabelValues("issued").Inc()

	oidcTokensCookiesExp := time.Until(stdClaims.Expiry.Time())
	// step: does the response have a refresh token and we do NOT ignore refresh tokens?
	if r.Config.EnableRefreshTokens && refreshToken != "" {
		var encrypted string
		var stdRefreshClaims *jwt.Claims
		stdRefreshClaims, err = r.verifyRefreshToken(scope, refreshToken, writer, req)
		if err != nil {
			return
		}

		oidcTokensCookiesExp = time.Until(stdRefreshClaims.Expiry.Time())
		encrypted, err = r.encryptToken(scope, refreshToken, r.Config.EncryptionKey, "refresh", writer)
		if err != nil {
			return
		}

		switch {
		case r.useStore():
			if err = r.StoreRefreshToken(req.Context(), rawAccessToken, encrypted, oidcTokensCookiesExp); err != nil {
				scope.Logger.Error(
					"failed to save the refresh token in the store",
					zap.Error(err),
					zap.String("sub", stdClaims.Subject),
					zap.String("email", customClaims.Email),
				)
				r.accessForbidden(writer, req)
				return
			}
		default:
			r.DropRefreshTokenCookie(req, writer, encrypted, oidcTokensCookiesExp)
		}
	}

	// step: decode the request variable
	redirectURI := "/"
	if req.URL.Query().Get("state") != "" {
		if encodedRequestURI, _ := req.Cookie(r.Config.CookieRequestURIName); encodedRequestURI != nil {
			redirectURI = r.getRequestURIFromCookie(scope, encodedRequestURI)
		}
	}

	if r.Config.PostLoginRedirectPath != "" && redirectURI == "/" {
		redirectURI = r.Config.PostLoginRedirectPath
	}

	var umaToken string
	var umaError error
	if r.Config.EnableUma {
		var methodScope *string
		if r.Config.EnableUmaMethodScope {
			ms := "method:" + req.Method
			methodScope = &ms
		}
		// we are not returning access forbidden immediately because we want to setup
		// access/refresh cookie as authentication already was done properly and user
		// could try to get new uma token/cookie, e.g in case he tried first to access
		// resource to which he doesn't have access

		token, erru := r.getRPT(req, redirectURI, accessToken, methodScope)
		umaError = erru
		if token != nil {
			umaToken = token.AccessToken
		}
	}

	// step: are we encrypting the access token?
	if r.Config.EnableEncryptedToken || r.Config.ForceEncryptedCookie {
		accessToken, err = r.encryptToken(scope, accessToken, r.Config.EncryptionKey, "access", writer)
		if err != nil {
			return
		}

		identityToken, err = r.encryptToken(scope, identityToken, r.Config.EncryptionKey, "id", writer)
		if err != nil {
			return
		}

		if r.Config.EnableUma && umaError == nil {
			umaToken, err = r.encryptToken(scope, umaToken, r.Config.EncryptionKey, "uma", writer)
			if err != nil {
				return
			}
		}
	}

	r.dropAccessTokenCookie(req, writer, accessToken, oidcTokensCookiesExp)
	r.dropIDTokenCookie(req, writer, identityToken, oidcTokensCookiesExp)

	if r.Config.EnableUma && umaError == nil {
		scope.Logger.Debug("got uma token", zap.String("uma", umaToken))
		r.dropUMATokenCookie(req, writer, umaToken, oidcTokensCookiesExp)
	}

	if umaError != nil {
		scope.Logger.Error(umaError.Error())
		r.accessForbidden(writer, req)
		return
	}

	scope.Logger.Debug("redirecting to", zap.String("location", redirectURI))
	r.redirectToURL(redirectURI, writer, req, http.StatusSeeOther)
}

/*
	loginHandler provide's a generic endpoint for clients to perform a user_credentials login to the provider
*/
//nolint:funlen,cyclop // refactor
func (r *OauthProxy) loginHandler(writer http.ResponseWriter, req *http.Request) {
	scope, assertOk := req.Context().Value(constant.ContextScopeName).(*RequestScope)

	if !assertOk {
		r.Log.Error(
			"assertion failed",
		)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	errorMsg, code, err := func() (string, int, error) {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			r.Config.OpenIDProviderTimeout,
		)

		if r.Config.SkipOpenIDProviderTLSVerify {
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			sslcli := &http.Client{Transport: tr}
			ctx = context.WithValue(ctx, oauth2.HTTPClient, sslcli)
		}

		defer cancel()

		if !r.Config.EnableLoginHandler {
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
		refreshToken := ""
		accessTokenObj, err := jwt.ParseSigned(token.AccessToken)

		if err != nil {
			return "unable to decode the access token", http.StatusNotImplemented, err
		}

		identity, err := ExtractIdentity(accessTokenObj)

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
		plainIDToken := idToken

		if r.Config.EnableEncryptedToken || r.Config.ForceEncryptedCookie {
			if accessToken, err = encryption.EncodeText(accessToken, r.Config.EncryptionKey); err != nil {
				scope.Logger.Error("unable to encode access token", zap.Error(err))
				return "unable to encode the access token",
					http.StatusInternalServerError,
					err
			}

			if idToken, err = encryption.EncodeText(idToken, r.Config.EncryptionKey); err != nil {
				scope.Logger.Error("unable to encode idToken token", zap.Error(err))
				return "unable to encode idToken token",
					http.StatusInternalServerError,
					err
			}
		}

		// step: does the response have a refresh token and we do NOT ignore refresh tokens?
		if r.Config.EnableRefreshTokens && token.RefreshToken != "" {
			refreshToken, err = encryption.EncodeText(token.RefreshToken, r.Config.EncryptionKey)

			if err != nil {
				scope.Logger.Error("failed to encrypt refresh token", zap.Error(err))
				return "failed to encrypt refresh token",
					http.StatusInternalServerError,
					err
			}

			// drop in the access token - cookie expiration = access token
			r.dropAccessTokenCookie(
				req,
				writer,
				accessToken,
				r.GetAccessCookieExpiration(token.RefreshToken),
			)

			r.dropIDTokenCookie(
				req,
				writer,
				idToken,
				r.GetAccessCookieExpiration(token.RefreshToken),
			)

			var expiration time.Duration
			// notes: not all idp refresh tokens are readable, google for example, so we attempt to decode into
			// a jwt and if possible extract the expiration, else we default to 10 days
			refreshTokenObj, errRef := jwt.ParseSigned(token.RefreshToken)

			if errRef != nil {
				scope.Logger.Error("failed to parse refresh token", zap.Error(errRef))
				return "failed to parse refresh token",
					http.StatusInternalServerError,
					errRef
			}

			stdRefreshClaims := &jwt.Claims{}

			err = refreshTokenObj.UnsafeClaimsWithoutVerification(stdRefreshClaims)

			if err != nil {
				expiration = 0
			} else {
				expiration = time.Until(stdRefreshClaims.Expiry.Time())
			}

			switch r.useStore() {
			case true:
				if err = r.StoreRefreshToken(req.Context(), token.AccessToken, refreshToken, expiration); err != nil {
					scope.Logger.Warn(
						"failed to save the refresh token in the store",
						zap.Error(err),
					)
				}
			default:
				r.DropRefreshTokenCookie(req, writer, refreshToken, expiration)
			}
		} else {
			r.dropAccessTokenCookie(
				req,
				writer,
				accessToken,
				time.Until(identity.ExpiresAt),
			)
			r.dropIDTokenCookie(
				req,
				writer,
				idToken,
				time.Until(identity.ExpiresAt),
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

		var resp TokenResponse

		if r.Config.EnableEncryptedToken {
			resp = TokenResponse{
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				ExpiresIn:    expiresIn,
				Scope:        tScope,
				TokenType:    token.TokenType,
			}
		} else {
			resp = TokenResponse{
				IDToken:      plainIDToken,
				AccessToken:  token.AccessToken,
				RefreshToken: refreshToken,
				ExpiresIn:    expiresIn,
				Scope:        tScope,
				TokenType:    token.TokenType,
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

/*
	logoutHandler performs a logout
	- if it's just a access token, the cookie is deleted
	- if the user has a refresh token, the token is invalidated by the provider
	- optionally, the user can be redirected by to a url
*/
//nolint:cyclop
func (r *OauthProxy) logoutHandler(writer http.ResponseWriter, req *http.Request) {
	// @check if the redirection is there
	var redirectURL string

	if r.Config.PostLogoutRedirectURI != "" {
		redirectURL = r.Config.PostLogoutRedirectURI
	} else {
		for k := range req.URL.Query() {
			if k == "redirect" {
				redirectURL = req.URL.Query().Get("redirect")

				if redirectURL == "" {
					// then we can default to redirection url
					redirectURL = strings.TrimSuffix(
						r.Config.RedirectionURL,
						"/oauth/callback",
					)
				}
			}
		}
	}

	scope, assertOk := req.Context().Value(constant.ContextScopeName).(*RequestScope)

	if !assertOk {
		r.Log.Error(
			"assertion failed",
		)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	// @step: drop the access token
	user, err := r.GetIdentity(req, r.Config.CookieAccessName, "")

	if err != nil {
		r.accessError(writer, req)
		return
	}

	// step: can either use the access token or the refresh token
	identityToken := user.RawToken

	//nolint:vetshadow
	if refresh, _, err := r.retrieveRefreshToken(req, user); err == nil {
		identityToken = refresh
	}

	idToken, _, err := r.retrieveIDToken(req)

	// we are doing it so that in case with no-redirects=true, we can pass
	// id token in authorization header
	if err != nil {
		idToken = user.RawToken
	}

	r.ClearAllCookies(req, writer)

	// @metric increment the logout counter
	oauthTokensMetric.WithLabelValues("logout").Inc()

	// step: check if the user has a state session and if so revoke it
	if r.useStore() {
		go func() {
			if err = r.DeleteRefreshToken(req.Context(), user.RawToken); err != nil {
				scope.Logger.Error(
					"unable to remove the refresh token from store",
					zap.Error(err),
				)
			}
		}()
	}

	// @check if we should redirect to the provider
	if r.Config.EnableLogoutRedirect {
		postLogoutParams := ""
		if r.Config.PostLogoutRedirectURI != "" {
			postLogoutParams = fmt.Sprintf(
				"?id_token_hint=%s&post_logout_redirect_uri=%s",
				idToken,
				url.QueryEscape(redirectURL),
			)
		}

		sendTo := fmt.Sprintf(
			"%s/protocol/openid-connect/logout%s",
			strings.TrimSuffix(
				r.Config.DiscoveryURL,
				"/.well-known/openid-configuration",
			),
			postLogoutParams,
		)

		r.redirectToURL(
			sendTo,
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
			r.Config.DiscoveryURL,
			"/.well-known/openid-configuration",
		),
	)

	revocationURL := utils.DefaultTo(r.Config.RevocationEndpoint, revokeDefault)

	// step: do we have a revocation endpoint?
	if revocationURL != "" {
		client := &http.Client{
			Timeout: r.Config.OpenIDProviderTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: r.Config.SkipOpenIDProviderTLSVerify,
				},
			},
		}

		// step: add the authentication headers
		encodedID := url.QueryEscape(r.Config.ClientID)
		encodedSecret := url.QueryEscape(r.Config.ClientSecret)

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
				zap.String("email", user.Email),
			)
		default:
			content, _ := io.ReadAll(response.Body)

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
func (r *OauthProxy) expirationHandler(wrt http.ResponseWriter, req *http.Request) {
	user, err := r.GetIdentity(req, r.Config.CookieAccessName, "")

	if err != nil {
		wrt.WriteHeader(http.StatusUnauthorized)
		return
	}

	if user.IsExpired() {
		wrt.WriteHeader(http.StatusUnauthorized)
		return
	}

	wrt.WriteHeader(http.StatusOK)
}

// tokenHandler display access token to screen
func (r *OauthProxy) tokenHandler(wrt http.ResponseWriter, req *http.Request) {
	user, err := r.GetIdentity(req, r.Config.CookieAccessName, "")

	if err != nil {
		r.accessError(wrt, req)
		return
	}

	token, err := jwt.ParseSigned(user.RawToken)

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

// proxyMetricsHandler forwards the request into the prometheus handler
func (r *OauthProxy) proxyMetricsHandler(wrt http.ResponseWriter, req *http.Request) {
	if r.Config.LocalhostMetrics {
		if !net.ParseIP(utils.RealIP(req)).IsLoopback() {
			r.accessForbidden(wrt, req)
			return
		}
	}
	r.metricsHandler.ServeHTTP(wrt, req)
}

// retrieveRefreshToken retrieves the refresh token from store or cookie
func (r *OauthProxy) retrieveRefreshToken(req *http.Request, user *UserContext) (string, string, error) {
	var token string
	var err error

	switch r.useStore() {
	case true:
		token, err = r.GetRefreshToken(req.Context(), user.RawToken)
	default:
		token, err = utils.GetRefreshTokenFromCookie(req, r.Config.CookieRefreshName)
	}

	if err != nil {
		return token, "", err
	}

	encrypted := token // returns encrypted, avoids encoding twice
	token, err = encryption.DecodeText(token, r.Config.EncryptionKey)
	return token, encrypted, err
}

// retrieveIDToken retrieves the id token from cookie
func (r *OauthProxy) retrieveIDToken(req *http.Request) (string, string, error) {
	var token string
	var err error
	var encrypted string

	token, err = utils.GetTokenInCookie(req, r.Config.CookieIDTokenName)

	if err != nil {
		return token, "", err
	}

	if r.Config.EnableEncryptedToken || r.Config.ForceEncryptedCookie {
		encrypted = token
		token, err = encryption.DecodeText(token, r.Config.EncryptionKey)
	}

	return token, encrypted, err
}

// discoveryHandler provides endpoint info
func (r *OauthProxy) discoveryHandler(wrt http.ResponseWriter, _ *http.Request) {
	resp := &DiscoveryResponse{
		ExpiredURL: r.Config.WithOAuthURI(constant.ExpiredURL),
		LogoutURL:  r.Config.WithOAuthURI(constant.LogoutURL),
		TokenURL:   r.Config.WithOAuthURI(constant.TokenURL),
		LoginURL:   r.Config.WithOAuthURI(constant.LoginURL),
	}

	respBody, err := json.Marshal(resp)

	if err != nil {
		r.Log.Error(
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
		r.Log.Error(
			"problem during response write",
			zap.String("error", err.Error()),
		)
	}
}
