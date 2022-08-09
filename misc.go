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
	"context"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v11"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"go.uber.org/zap"
	"gopkg.in/square/go-jose.v2/jwt"
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

// revokeProxy is responsible to stopping the middleware from proxying the request
func (r *oauthProxy) revokeProxy(w http.ResponseWriter, req *http.Request) context.Context {
	var scope *RequestScope
	ctxVal := req.Context().Value(constant.ContextScopeName)

	switch ctxVal {
	case nil:
		scope = &RequestScope{AccessDenied: true}
	default:
		var assertOk bool
		scope, assertOk = ctxVal.(*RequestScope)

		if !assertOk {
			r.log.Error("assertion failed")
			scope = &RequestScope{AccessDenied: true}
		}
	}

	scope.AccessDenied = true

	return context.WithValue(req.Context(), constant.ContextScopeName, scope)
}

// accessForbidden redirects the user to the forbidden page
func (r *oauthProxy) accessForbidden(wrt http.ResponseWriter, req *http.Request) context.Context {
	wrt.WriteHeader(http.StatusForbidden)
	// are we using a custom http template for 403?
	if r.config.hasCustomForbiddenPage() {
		name := path.Base(r.config.ForbiddenPage)

		if err := r.Render(wrt, name, r.config.Tags); err != nil {
			r.log.Error(
				"failed to render the template",
				zap.Error(err),
				zap.String("template", name),
			)
		}
	}

	return r.revokeProxy(wrt, req)
}

// accessError redirects the user to the error page
func (r *oauthProxy) accessError(wrt http.ResponseWriter, req *http.Request) context.Context {
	wrt.WriteHeader(http.StatusBadRequest)
	// are we using a custom http template for 400?
	if r.config.hasCustomErrorPage() {
		name := path.Base(r.config.ErrorPage)

		if err := r.Render(wrt, name, r.config.Tags); err != nil {
			r.log.Error(
				"failed to render the template",
				zap.Error(err),
				zap.String("template", name),
			)
		}
	}

	return r.revokeProxy(wrt, req)
}

// redirectToURL redirects the user and aborts the context
func (r *oauthProxy) redirectToURL(url string, wrt http.ResponseWriter, req *http.Request, statusCode int) context.Context {
	wrt.Header().Add(
		"Cache-Control",
		"no-cache, no-store, must-revalidate, max-age=0",
	)

	http.Redirect(wrt, req, url, statusCode)
	return r.revokeProxy(wrt, req)
}

// redirectToAuthorization redirects the user to authorization handler
func (r *oauthProxy) redirectToAuthorization(wrt http.ResponseWriter, req *http.Request) context.Context {
	if r.config.NoRedirects && !r.config.EnableUma {
		wrt.WriteHeader(http.StatusUnauthorized)
		return r.revokeProxy(wrt, req)
	}

	if r.config.EnableUma {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			r.config.OpenIDProviderTimeout,
		)

		defer cancel()

		matchingURI := true

		resourceParam := gocloak.GetResourceParams{
			URI:         &req.URL.Path,
			MatchingURI: &matchingURI,
		}

		r.pat.m.Lock()
		token := r.pat.Token.AccessToken
		r.pat.m.Unlock()

		resources, err := r.idpClient.GetResourcesClient(
			ctx,
			token,
			r.config.Realm,
			resourceParam,
		)

		if err != nil {
			r.log.Error(
				"problem getting resources for path",
				zap.String("path", req.URL.Path),
				zap.Error(err),
			)
			wrt.WriteHeader(http.StatusUnauthorized)
			return r.revokeProxy(wrt, req)
		}

		if len(resources) == 0 {
			r.log.Info(
				"no resources for path",
				zap.String("path", req.URL.Path),
			)
			wrt.WriteHeader(http.StatusUnauthorized)
			return r.revokeProxy(wrt, req)
		}

		resourceID := resources[0].ID
		resourceScopes := make([]string, 0)

		if len(*resources[0].ResourceScopes) == 0 {
			r.log.Error(
				"missingg scopes for resource in IDP provider",
				zap.String("resourceID", *resourceID),
			)
			wrt.WriteHeader(http.StatusUnauthorized)
			return r.revokeProxy(wrt, req)
		}

		for _, scope := range *resources[0].ResourceScopes {
			resourceScopes = append(resourceScopes, *scope.Name)
		}

		permissions := []gocloak.CreatePermissionTicketParams{
			{
				ResourceID:     resourceID,
				ResourceScopes: &resourceScopes,
			},
		}

		permTicket, err := r.idpClient.CreatePermissionTicket(
			ctx,
			token,
			r.config.Realm,
			permissions,
		)

		if err != nil {
			r.log.Error(
				"problem getting permission ticket for resourceId",
				zap.String("resourceID", *resourceID),
				zap.Error(err),
			)
			wrt.WriteHeader(http.StatusUnauthorized)
			return r.revokeProxy(wrt, req)
		}

		permHeader := fmt.Sprintf(
			`realm="%s", as_uri="%s", ticket="%s"`,
			r.config.Realm,
			r.config.DiscoveryURI.Host,
			*permTicket.Ticket,
		)

		wrt.Header().Add(
			"WWW-Authenticate",
			permHeader,
		)
		wrt.WriteHeader(http.StatusUnauthorized)
		return r.revokeProxy(wrt, req)
	}

	// step: add a state referrer to the authorization page
	uuid := r.writeStateParameterCookie(req, wrt)
	authQuery := fmt.Sprintf("?state=%s", uuid)

	// step: if verification is switched off, we can't authorization
	if r.config.SkipTokenVerification {
		r.log.Error(
			"refusing to redirection to authorization endpoint, " +
				"skip token verification switched on",
		)

		wrt.WriteHeader(http.StatusForbidden)
		return r.revokeProxy(wrt, req)
	}

	r.redirectToURL(
		r.config.WithOAuthURI(constant.AuthorizationURL+authQuery),
		wrt,
		req,
		http.StatusSeeOther,
	)

	return r.revokeProxy(wrt, req)
}

// getAccessCookieExpiration calculates the expiration of the access token cookie
func (r *oauthProxy) getAccessCookieExpiration(refresh string) time.Duration {
	// notes: by default the duration of the access token will be the configuration option, if
	// however we can decode the refresh token, we will set the duration to the duration of the
	// refresh token
	duration := r.config.AccessTokenDuration

	webToken, err := jwt.ParseSigned(refresh)

	if err != nil {
		r.log.Error("unable to parse token")
	}

	if ident, err := extractIdentity(webToken); err == nil {
		delta := time.Until(ident.expiresAt)

		if delta > 0 {
			duration = delta
		}

		r.log.Debug(
			"parsed refresh token with new duration",
			zap.Duration("new duration", delta),
		)
	} else {
		r.log.Debug("refresh token is opaque and cannot be used to extend calculated duration")
	}

	return duration
}
