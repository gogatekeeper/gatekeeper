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
	"context"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v12"
	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	configcore "github.com/gogatekeeper/gatekeeper/pkg/config/core"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
)

// filterCookies is responsible for censoring any cookies we don't want sent
func filterCookies(req *http.Request, filter []string) error {
	// @NOTE: there doesn't appear to be a way of removing a cookie from the http.Request as
	// AddCookie() just append
	cookies := req.Cookies()
	// @step: empty the current cookies
	req.Header.Set("Cookie", "")
	// @step: iterate the cookies and filter out anything we
	for _, cookie := range cookies {
		var found bool
		// @step: does this cookie match our filter?
		for _, n := range filter {
			if strings.HasPrefix(cookie.Name, n) {
				req.AddCookie(&http.Cookie{Name: cookie.Name, Value: "censored"})
				found = true
				break
			}
		}

		if !found {
			req.AddCookie(cookie)
		}
	}

	return nil
}

// revokeProxy is responsible for stopping middleware from proxying the request
func revokeProxy(logger *zap.Logger, req *http.Request) context.Context {
	var scope *RequestScope
	ctxVal := req.Context().Value(constant.ContextScopeName)

	switch ctxVal {
	case nil:
		scope = &RequestScope{AccessDenied: true}
	default:
		var assertOk bool
		scope, assertOk = ctxVal.(*RequestScope)
		if !assertOk {
			logger.Error(apperrors.ErrAssertionFailed.Error())
			scope = &RequestScope{AccessDenied: true}
		}
	}

	scope.AccessDenied = true

	return context.WithValue(req.Context(), constant.ContextScopeName, scope)
}

// accessForbidden redirects the user to the forbidden page
func accessForbidden(
	logger *zap.Logger,
	httpStatus int,
	page string,
	tags map[string]string,
	tmpl *template.Template,
) func(wrt http.ResponseWriter, req *http.Request) context.Context {
	return func(wrt http.ResponseWriter, req *http.Request) context.Context {
		wrt.WriteHeader(httpStatus)
		// are we using a custom http template for 403?
		if page != "" {
			name := path.Base(page)

			if err := tmpl.ExecuteTemplate(wrt, name, tags); err != nil {
				logger.Error(
					"failed to render the template",
					zap.Error(err),
					zap.String("template", name),
				)
			}
		}

		return revokeProxy(logger, req)
	}
}

// renders customSignInPage
func customSignInPage(
	logger *zap.Logger,
	page string,
	tags map[string]string,
	tmpl *template.Template,
) func(wrt http.ResponseWriter, authURL string) {
	return func(wrt http.ResponseWriter, authURL string) {
		wrt.WriteHeader(http.StatusOK)
		name := path.Base(page)
		model := make(map[string]string)
		model["redirect"] = authURL
		mTags := utils.MergeMaps(model, tags)

		if err := tmpl.ExecuteTemplate(wrt, name, mTags); err != nil {
			logger.Error(
				"failed to render the template",
				zap.Error(err),
				zap.String("template", name),
			)
		}
	}
}

// redirectToURL redirects the user and aborts the context
func redirectToURL(
	logger *zap.Logger,
	url string,
	wrt http.ResponseWriter,
	req *http.Request,
	statusCode int,
) context.Context {
	wrt.Header().Add(
		"Cache-Control",
		"no-cache, no-store, must-revalidate, max-age=0",
	)

	http.Redirect(wrt, req, url, statusCode)
	return revokeProxy(logger, req)
}

// WithOAuthURI returns the oauth uri
func WithOAuthURI(baseURI string, oauthURI string) func(uri string) string {
	return func(uri string) string {
		uri = strings.TrimPrefix(uri, "/")
		if baseURI != "" {
			return fmt.Sprintf("%s/%s/%s", baseURI, oauthURI, uri)
		}
		return fmt.Sprintf("%s/%s", oauthURI, uri)
	}
}

// redirectToAuthorization redirects the user to authorization handler
func (r *OauthProxy) redirectToAuthorization(wrt http.ResponseWriter, req *http.Request) context.Context {
	if r.Config.NoRedirects {
		wrt.WriteHeader(http.StatusUnauthorized)
		return revokeProxy(r.Log, req)
	}

	// step: add a state referrer to the authorization page
	uuid := r.Cm.DropStateParameterCookie(req, wrt)
	authQuery := fmt.Sprintf("?state=%s", uuid)

	// step: if verification is switched off, we can't authorization
	if r.Config.SkipTokenVerification {
		r.Log.Error(
			"refusing to redirection to authorization endpoint, " +
				"skip token verification switched on",
		)

		wrt.WriteHeader(http.StatusForbidden)
		return revokeProxy(r.Log, req)
	}

	url := r.WithOAuthURI(constant.AuthorizationURL + authQuery)

	if r.Config.NoProxy && !r.Config.NoRedirects {
		xForwardedHost := req.Header.Get("X-Forwarded-Host")
		xProto := req.Header.Get("X-Forwarded-Proto")

		if xForwardedHost == "" || xProto == "" {
			r.Log.Error(apperrors.ErrForwardAuthMissingHeaders.Error())

			wrt.WriteHeader(http.StatusForbidden)
			return revokeProxy(r.Log, req)
		}

		url = fmt.Sprintf(
			"%s://%s%s",
			xProto,
			xForwardedHost,
			url,
		)
	}

	r.Log.Debug("redirecting to url", zap.String("url", url))

	redirectToURL(
		r.Log,
		url,
		wrt,
		req,
		http.StatusSeeOther,
	)

	return revokeProxy(r.Log, req)
}

// GetAccessCookieExpiration calculates the expiration of the access token cookie
func (r *OauthProxy) GetAccessCookieExpiration(refresh string) time.Duration {
	// notes: by default the duration of the access token will be the configuration option, if
	// however we can decode the refresh token, we will set the duration to the duration of the
	// refresh token
	duration := r.Config.AccessTokenDuration

	webToken, err := jwt.ParseSigned(refresh)

	if err != nil {
		r.Log.Error("unable to parse token")
	}

	if ident, err := ExtractIdentity(webToken); err == nil {
		delta := time.Until(ident.ExpiresAt)

		if delta > 0 {
			duration = delta
		}

		r.Log.Debug(
			"parsed refresh token with new duration",
			zap.Duration("new duration", delta),
		)
	} else {
		r.Log.Debug("refresh token is opaque and cannot be used to extend calculated duration")
	}

	return duration
}

//nolint:cyclop
func (r *OauthProxy) getPAT(done chan bool) {
	retry := 0
	r.pat = &PAT{}
	initialized := false
	rConfig := *r.Config
	clientID := rConfig.ClientID
	clientSecret := rConfig.ClientSecret
	realm := rConfig.Realm
	timeout := rConfig.OpenIDProviderTimeout
	patRetryCount := rConfig.PatRetryCount
	patRetryInterval := rConfig.PatRetryInterval
	grantType := configcore.GrantTypeClientCreds

	if rConfig.EnableForwarding && rConfig.ForwardingGrantType == configcore.GrantTypeUserCreds {
		grantType = configcore.GrantTypeUserCreds
	}

	for {
		if retry > 0 {
			r.Log.Info(
				"retrying fetching PAT token",
				zap.Int("retry", retry),
			)
		}

		ctx, cancel := context.WithTimeout(
			context.Background(),
			timeout,
		)

		var token *gocloak.JWT
		var err error

		switch grantType {
		case configcore.GrantTypeClientCreds:
			token, err = r.IdpClient.LoginClient(
				ctx,
				clientID,
				clientSecret,
				realm,
			)
		case configcore.GrantTypeUserCreds:
			token, err = r.IdpClient.Login(
				ctx,
				clientID,
				clientSecret,
				realm,
				rConfig.ForwardingUsername,
				rConfig.ForwardingPassword,
			)
		default:
			r.Log.Error(
				"Chosen grant type is not supported",
				zap.String("grant_type", grantType),
			)
			os.Exit(11)
		}

		if err != nil {
			retry++
			r.Log.Error("problem getting PAT token", zap.Error(err))

			if retry >= patRetryCount {
				cancel()
				os.Exit(10)
			}

			<-time.After(patRetryInterval)
			continue
		}

		r.pat.m.Lock()
		r.pat.Token = token
		r.pat.m.Unlock()

		if !initialized {
			done <- true
		}

		initialized = true

		parsedToken, err := jwt.ParseSigned(token.AccessToken)

		if err != nil {
			retry++
			r.Log.Error("failed to parse the access token", zap.Error(err))
			<-time.After(patRetryInterval)
			continue
		}

		stdClaims := &jwt.Claims{}

		err = parsedToken.UnsafeClaimsWithoutVerification(stdClaims)

		if err != nil {
			retry++
			r.Log.Error("unable to parse access token for claims", zap.Error(err))
			<-time.After(patRetryInterval)
			continue
		}

		retry = 0
		expiration := stdClaims.Expiry.Time()

		refreshIn := utils.GetWithin(expiration, 0.85)

		r.Log.Info(
			"waiting for expiration of access token",
			zap.Float64("refresh_in", refreshIn.Seconds()),
		)

		<-time.After(refreshIn)
	}
}

func (r *OauthProxy) WithUMAIdentity(
	req *http.Request,
	targetPath string,
	user *UserContext,
	authzFunc func(targetPath string, userPerms authorization.Permissions) (authorization.AuthzDecision, error),
) (authorization.AuthzDecision, error) {
	umaUser, err := r.GetIdentity(req, r.Config.CookieUMAName, constant.UMAHeader)
	if err != nil {
		return authorization.DeniedAuthz, err
	}

	err = r.verifyUmaToken(user, umaUser, req)
	if err != nil {
		return authorization.DeniedAuthz, err
	}

	return authzFunc(targetPath, umaUser.Permissions)
}

// getRPT retrieves relaying party token
func (r *OauthProxy) getRPT(
	req *http.Request,
	targetPath string,
	userToken string,
	methodScope *string,
) (*gocloak.JWT, error) {
	ctx, cancel := context.WithTimeout(
		req.Context(),
		r.Config.OpenIDProviderTimeout,
	)

	defer cancel()

	matchingURI := true
	resourceParam := gocloak.GetResourceParams{
		URI:         &targetPath,
		MatchingURI: &matchingURI,
		Scope:       methodScope,
	}

	r.pat.m.RLock()
	pat := r.pat.Token.AccessToken
	r.pat.m.RUnlock()

	resources, err := r.IdpClient.GetResourcesClient(
		ctx,
		pat,
		r.Config.Realm,
		resourceParam,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%s %s",
			apperrors.ErrNoIDPResourceForPath.Error(),
			err,
		)
	}

	if len(resources) == 0 {
		return nil, apperrors.ErrNoIDPResourceForPath
	}
	if len(resources) > 1 {
		return nil, apperrors.ErrTooManyResources
	}

	resourceID := resources[0].ID
	resourceScopes := make([]string, 0)
	if len(*resources[0].ResourceScopes) == 0 {
		return nil, fmt.Errorf(
			"%w, resource: %s",
			apperrors.ErrMissingScopesForResource,
			*resourceID,
		)
	}

	if methodScope != nil {
		resourceScopes = append(resourceScopes, *methodScope)
	} else {
		for _, scope := range *resources[0].ResourceScopes {
			resourceScopes = append(resourceScopes, *scope.Name)
		}
	}

	permissions := []gocloak.CreatePermissionTicketParams{
		{
			ResourceID:     resourceID,
			ResourceScopes: &resourceScopes,
		},
	}

	permTicket, err := r.IdpClient.CreatePermissionTicket(
		ctx,
		pat,
		r.Config.Realm,
		permissions,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%s resource: %s %w",
			apperrors.ErrPermissionTicketForResourceID.Error(),
			*resourceID,
			err,
		)
	}

	grantType := configcore.GrantTypeUmaTicket

	rptOptions := gocloak.RequestingPartyTokenOptions{
		GrantType: &grantType,
		Ticket:    permTicket.Ticket,
	}

	if userToken == "" {
		userToken = pat
	}

	rpt, err := r.IdpClient.GetRequestingPartyToken(ctx, userToken, r.Config.Realm, rptOptions)
	if err != nil {
		return nil, fmt.Errorf(
			"%s resource: %s %w",
			apperrors.ErrRetrieveRPT.Error(),
			*resourceID,
			err,
		)
	}

	return rpt, nil
}

func (r *OauthProxy) getCodeFlowTokens(
	scope *RequestScope,
	writer http.ResponseWriter,
	req *http.Request,
) (string, string, string, error) {
	// step: ensure we have a authorization code
	code := req.URL.Query().Get("code")

	if code == "" {
		r.accessError(writer, req)
		return "", "", "", fmt.Errorf("missing auth code")
	}

	conf := r.newOAuth2Config(r.getRedirectionURL(writer, req))

	var codeVerifier *http.Cookie

	if r.Config.EnablePKCE {
		var err error
		codeVerifier, err = req.Cookie(r.Config.CookiePKCEName)
		if err != nil {
			scope.Logger.Error("problem getting pkce cookie", zap.Error(err))
			r.accessForbidden(writer, req)
			return "", "", "", err
		}
	}

	resp, err := exchangeAuthenticationCode(
		conf,
		code,
		codeVerifier,
		r.Config.SkipOpenIDProviderTLSVerify,
	)
	if err != nil {
		scope.Logger.Error("unable to exchange code for access token", zap.Error(err))
		r.accessForbidden(writer, req)
		return "", "", "", err
	}

	idToken, assertOk := resp.Extra("id_token").(string)
	if !assertOk {
		scope.Logger.Error("unable to obtain id token", zap.Error(err))
		r.accessForbidden(writer, req)
		return "", "", "", err
	}

	return resp.AccessToken, idToken, resp.RefreshToken, nil
}

func (r *OauthProxy) verifyUmaToken(
	accessUserCtx *UserContext,
	umaUserCtx *UserContext,
	req *http.Request,
) error {
	// make sure somebody doesn't sent one user access token
	// and others user valid uma token in one request
	if umaUserCtx.ID != accessUserCtx.ID {
		return apperrors.ErrAccessMismatchUmaToken
	}

	verifier := r.Provider.Verifier(
		&oidc3.Config{
			ClientID:          r.Config.ClientID,
			SkipClientIDCheck: r.Config.SkipAccessTokenClientIDCheck,
			SkipIssuerCheck:   r.Config.SkipAccessTokenIssuerCheck,
		},
	)

	ctx, cancel := context.WithTimeout(req.Context(), r.Config.OpenIDProviderTimeout)
	defer cancel()

	_, err := verifier.Verify(ctx, umaUserCtx.RawToken)
	if err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			return apperrors.ErrUMATokenExpired
		}
		return fmt.Errorf("%s %w", apperrors.ErrTokenVerificationFailure.Error(), err)
	}

	return nil
}

func (r *OauthProxy) verifyOIDCTokens(
	scope *RequestScope,
	rawAccessToken string,
	rawIDToken string,
	writer http.ResponseWriter,
	req *http.Request,
) (*jwt.Claims, *custClaims, error) {
	var idToken *oidc3.IDToken
	var err error

	verifier := r.Provider.Verifier(&oidc3.Config{ClientID: r.Config.ClientID})

	ctx, cancel := context.WithTimeout(
		context.Background(),
		r.Config.OpenIDProviderTimeout,
	)

	defer cancel()

	idToken, err = verifier.Verify(ctx, rawIDToken)
	if err != nil {
		scope.Logger.Error(apperrors.ErrVerifyIDToken.Error(), zap.Error(err))
		r.accessForbidden(writer, req)
		return nil, nil, err
	}

	token, err := jwt.ParseSigned(rawIDToken)
	if err != nil {
		scope.Logger.Error(apperrors.ErrParseIDToken.Error(), zap.Error(err))
		r.accessForbidden(writer, req)
		return nil, nil, err
	}

	stdClaims := &jwt.Claims{}
	customClaims := &custClaims{}

	err = token.UnsafeClaimsWithoutVerification(stdClaims, customClaims)
	if err != nil {
		scope.Logger.Error(apperrors.ErrParseIDTokenClaims.Error(), zap.Error(err))
		r.accessForbidden(writer, req)
		return nil, nil, err
	}

	// check https://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken - at_hash
	// keycloak seems doesnt support yet at_hash
	// https://stackoverflow.com/questions/60818373/configure-keycloak-to-include-an-at-hash-claim-in-the-id-token
	if idToken.AccessTokenHash != "" {
		err = idToken.VerifyAccessToken(rawAccessToken)

		if err != nil {
			scope.Logger.Error(apperrors.ErrVerifyAccessToken.Error(), zap.Error(err))
			r.accessForbidden(writer, req)
			return nil, nil, err
		}
	}

	accToken, err := jwt.ParseSigned(rawAccessToken)
	if err != nil {
		scope.Logger.Error(apperrors.ErrParseAccessToken.Error())
		r.accessForbidden(writer, req)
		return nil, nil, err
	}

	token = accToken
	stdClaims = &jwt.Claims{}
	customClaims = &custClaims{}

	err = token.UnsafeClaimsWithoutVerification(stdClaims, customClaims)
	if err != nil {
		scope.Logger.Error(apperrors.ErrParseAccessTokenClaims.Error(), zap.Error(err))
		r.accessForbidden(writer, req)
		return nil, nil, err
	}

	scope.Logger.Debug(
		"issuing access token for user",
		zap.String("access token", rawAccessToken),
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

	return stdClaims, customClaims, nil
}

func (r *OauthProxy) verifyRefreshToken(
	scope *RequestScope,
	rawRefreshToken string,
	writer http.ResponseWriter,
	req *http.Request,
) (*jwt.Claims, error) {
	refreshToken, err := jwt.ParseSigned(rawRefreshToken)
	if err != nil {
		scope.Logger.Error(apperrors.ErrParseRefreshToken.Error(), zap.Error(err))
		writer.WriteHeader(http.StatusInternalServerError)
		return nil, err
	}

	stdRefreshClaims := &jwt.Claims{}
	err = refreshToken.UnsafeClaimsWithoutVerification(stdRefreshClaims)
	if err != nil {
		scope.Logger.Error(apperrors.ErrParseRefreshTokenClaims.Error(), zap.Error(err))
		r.accessForbidden(writer, req)
		return nil, err
	}

	return stdRefreshClaims, nil
}

func (r *OauthProxy) encryptToken(
	scope *RequestScope,
	rawToken string,
	encKey string,
	tokenType string,
	writer http.ResponseWriter,
) (string, error) {
	var err error
	var encrypted string
	if encrypted, err = encryption.EncodeText(rawToken, encKey); err != nil {
		scope.Logger.Error(
			"failed to encrypt token",
			zap.Error(err),
			zap.String("type", tokenType),
		)
		writer.WriteHeader(http.StatusInternalServerError)
		return "", err
	}
	return encrypted, nil
}

func (r *OauthProxy) getRequestURIFromCookie(
	scope *RequestScope,
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

func (r *OauthProxy) refreshUmaToken(
	req *http.Request,
	targetPath string,
	user *UserContext,
	methodScope *string,
) (*UserContext, error) {
	tok, err := r.getRPT(req, targetPath, user.RawToken, methodScope)
	if err != nil {
		return nil, err
	}

	token, err := jwt.ParseSigned(tok.AccessToken)
	if err != nil {
		return nil, err
	}

	umaUser, err := ExtractIdentity(token)
	if err != nil {
		return nil, err
	}

	umaUser.RawToken = tok.AccessToken
	return umaUser, nil
}
