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

	"github.com/Nerzal/gocloak/v11"
	"go.uber.org/zap"
)

/*
	proxyMiddleware is responsible for handles reverse proxy
	request to the upstream endpoint
*/
//nolint:cyclop
func (r *oauthProxy) proxyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
		next.ServeHTTP(wrt, req)

		// @step: retrieve the request scope
		ctxVal := req.Context().Value(contextScopeName)
		var scope *RequestScope
		if ctxVal != nil {
			var assertOk bool
			scope, assertOk = ctxVal.(*RequestScope)

			if !assertOk {
				r.log.Error(
					"assertion failed",
				)
				return
			}

			if scope.AccessDenied {
				return
			}
		}

		// @step: add the proxy forwarding headers
		req.Header.Set("X-Real-IP", realIP(req))
		if xff := req.Header.Get(headerXForwardedFor); xff == "" {
			req.Header.Set("X-Forwarded-For", realIP(req))
		} else {
			req.Header.Set("X-Forwarded-For", xff)
		}
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", req.Header.Get("X-Forwarded-Proto"))

		if len(r.config.CorsOrigins) > 0 {
			// if CORS is enabled by Gatekeeper, do not propagate CORS requests upstream
			req.Header.Del("Origin")
		}
		// @step: add any custom headers to the request
		for k, v := range r.config.Headers {
			req.Header.Set(k, v)
		}

		// @note: by default goproxy only provides a forwarding proxy, thus all requests have to be absolute and we must update the host headers
		req.URL.Host = r.endpoint.Host
		req.URL.Scheme = r.endpoint.Scheme
		// Restore the unprocessed original path, so that we pass upstream exactly what we received
		// as the resource request.
		if scope != nil {
			req.URL.Path = scope.Path
			req.URL.RawPath = scope.RawPath
		}
		if v := req.Header.Get("Host"); v != "" {
			req.Host = v
			req.Header.Del("Host")
		} else if !r.config.PreserveHost {
			req.Host = r.endpoint.Host
		}

		if isUpgradedConnection(req) {
			r.log.Debug("upgrading the connnection", zap.String("client_ip", req.RemoteAddr))
			if err := tryUpdateConnection(req, wrt, r.endpoint); err != nil {
				r.log.Error("failed to upgrade connection", zap.Error(err))
				wrt.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		}

		r.upstream.ServeHTTP(wrt, req)
	})
}

// forwardProxyHandler is responsible for signing outbound requests
func (r *oauthProxy) forwardProxyHandler() func(*http.Request, *http.Response) {
	return func(req *http.Request, resp *http.Response) {
		var token string

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
			pat := r.pat.Token.AccessToken
			r.pat.m.Unlock()

			resources, err := r.idpClient.GetResourcesClient(
				ctx,
				pat,
				r.config.Realm,
				resourceParam,
			)

			if err != nil {
				r.log.Error(
					"problem getting resources for path",
					zap.String("path", req.URL.Path),
					zap.Error(err),
				)
				return
			}

			if len(resources) == 0 {
				r.log.Info(
					"no resources for path",
					zap.String("path", req.URL.Path),
				)
				return
			}

			resourceID := resources[0].ID
			resourceScopes := make([]string, 0)

			if len(*resources[0].ResourceScopes) == 0 {
				r.log.Error(
					"missing scopes for resource in IDP provider",
					zap.String("resourceID", *resourceID),
				)
				return
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
				pat,
				r.config.Realm,
				permissions,
			)

			if err != nil {
				r.log.Error(
					"problem getting permission ticket for resourceId",
					zap.String("resourceID", *resourceID),
					zap.Error(err),
				)
				return
			}

			grantType := GrantTypeUmaTicket

			rptOptions := gocloak.RequestingPartyTokenOptions{
				GrantType: &grantType,
				Ticket:    permTicket.Ticket,
			}

			rpt, err := r.idpClient.GetRequestingPartyToken(ctx, pat, r.config.Realm, rptOptions)

			if err != nil {
				r.log.Error(
					"problem getting RPT for resource (hint: do you have permissions assigned to resource?)",
					zap.String("resourceID", *resourceID),
					zap.Error(err),
				)
				return
			}

			token = rpt.AccessToken
		} else {
			r.pat.m.Lock()
			token = r.pat.Token.AccessToken
			r.pat.m.Unlock()
		}

		hostname := req.Host
		req.URL.Host = hostname
		// is the host being signed?
		if len(r.config.ForwardingDomains) == 0 || containsSubString(hostname, r.config.ForwardingDomains) {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			req.Header.Set("X-Forwarded-Agent", prog)
		}
	}
}
