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
	"regexp"
	"strings"
	"time"

	uuid "github.com/gofrs/uuid"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"

	"github.com/PuerkitoBio/purell"
	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/unrolled/secure"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	// normalizeFlags is the options to purell
	normalizeFlags purell.NormalizationFlags = purell.FlagRemoveDotSegments | purell.FlagRemoveDuplicateSlashes
)

// entrypointMiddleware is custom filtering for incoming requests
func (r *oauthProxy) entrypointMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
		// @step: create a context for the request
		scope := &RequestScope{}
		// Save the exact formatting of the incoming request so we can use it later
		scope.Path = req.URL.Path
		scope.RawPath = req.URL.RawPath
		scope.Logger = r.log

		// We want to Normalize the URL so that we can more easily and accurately
		// parse it to apply resource protection rules.
		purell.NormalizeURL(req.URL, normalizeFlags)

		// ensure we have a slash in the url
		if !strings.HasPrefix(req.URL.Path, "/") {
			req.URL.Path = "/" + req.URL.Path
		}
		req.URL.RawPath = req.URL.EscapedPath()

		resp := middleware.NewWrapResponseWriter(wrt, 1)
		start := time.Now()
		// All the processing, including forwarding the request upstream and getting the response,
		// happens here in this chain.
		next.ServeHTTP(resp, req.WithContext(context.WithValue(req.Context(), contextScopeName, scope)))

		// @metric record the time taken then response code
		latencyMetric.Observe(time.Since(start).Seconds())
		statusMetric.WithLabelValues(fmt.Sprintf("%d", resp.Status()), req.Method).Inc()

		// place back the original uri for any later consumers
		req.URL.Path = scope.Path
		req.URL.RawPath = scope.RawPath
	})
}

// requestIDMiddleware is responsible for adding a request id if none found
func (r *oauthProxy) requestIDMiddleware(header string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			if v := req.Header.Get(header); v == "" {
				uuid, err := uuid.NewV1()

				if err != nil {
					wrt.WriteHeader(http.StatusInternalServerError)
				}

				req.Header.Set(header, uuid.String())
			}

			next.ServeHTTP(wrt, req)
		})
	}
}

// loggingMiddleware is a custom http logger
func (r *oauthProxy) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		resp, assertOk := w.(middleware.WrapResponseWriter)

		if !assertOk {
			r.log.Error(
				"Assertion failed",
			)
			return
		}

		scope, assertOk := req.Context().Value(contextScopeName).(*RequestScope)

		if !assertOk {
			r.log.Error(
				"Assertion failed",
			)
			return
		}

		if r.config.Verbose {
			requestLogger := r.log.With(
				zap.Any("headers", req.Header),
			)
			scope.Logger = requestLogger
		}

		next.ServeHTTP(resp, req)

		addr := req.RemoteAddr

		if req.URL.Path == req.URL.RawPath || req.URL.RawPath == "" {
			scope.Logger.Info("client request",
				zap.Duration("latency", time.Since(start)),
				zap.Int("status", resp.Status()),
				zap.Int("bytes", resp.BytesWritten()),
				zap.String("client_ip", addr),
				zap.String("method", req.Method),
				zap.String("path", req.URL.Path))
		} else {
			scope.Logger.Info("client request",
				zap.Duration("latency", time.Since(start)),
				zap.Int("status", resp.Status()),
				zap.Int("bytes", resp.BytesWritten()),
				zap.String("client_ip", addr),
				zap.String("method", req.Method),
				zap.String("path", req.URL.Path),
				zap.String("raw path", req.URL.RawPath))
		}
	})
}

// authenticationMiddleware is responsible for verifying the access token
// nolint:funlen
func (r *oauthProxy) authenticationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			scope, assertOk := req.Context().Value(contextScopeName).(*RequestScope)

			if !assertOk {
				r.log.Error(
					"Assertion failed",
				)
				return
			}

			clientIP := req.RemoteAddr

			// grab the user identity from the request
			user, err := r.getIdentity(req)

			if err != nil {
				scope.Logger.Error(
					"no session found in request, redirecting for authorization",
					zap.Error(err),
				)

				next.ServeHTTP(wrt, req.WithContext(r.redirectToAuthorization(wrt, req)))
				return
			}

			scope.Identity = user
			ctx := context.WithValue(req.Context(), contextScopeName, scope)

			// step: skip if we are running skip-token-verification
			if r.config.SkipTokenVerification {
				scope.Logger.Warn(
					"skip token verification enabled, " +
						"skipping verification - TESTING ONLY",
				)

				if user.isExpired() {
					scope.Logger.Error(
						"the session has expired and verification switch off",
						zap.String("client_ip", clientIP),
						zap.String("username", user.name),
						zap.String("sub", user.id),
						zap.String("expired_on", user.expiresAt.String()),
					)

					next.ServeHTTP(wrt, req.WithContext(r.redirectToAuthorization(wrt, req)))
					return
				}
			} else { //nolint:gocritic
				verifier := r.provider.Verifier(
					&oidc3.Config{
						ClientID:          r.config.ClientID,
						SkipClientIDCheck: r.config.SkipAccessTokenClientIDCheck,
						SkipIssuerCheck:   r.config.SkipAccessTokenIssuerCheck,
					},
				)

				_, err := verifier.Verify(context.Background(), user.rawToken)

				if err != nil {
					// step: if the error post verification is anything other than a token
					// expired error we immediately throw an access forbidden - as there is
					// something messed up in the token
					if !strings.Contains(err.Error(), "token is expired") {
						scope.Logger.Error(
							"access token failed verification",
							zap.String("client_ip", clientIP),
							zap.Error(err),
						)

						next.ServeHTTP(wrt, req.WithContext(r.accessForbidden(wrt, req)))
						return
					}

					// step: check if we are refreshing the access tokens and if not re-auth
					if !r.config.EnableRefreshTokens {
						scope.Logger.Error(
							"session expired and access token refreshing is disabled",
							zap.String("client_ip", clientIP),
							zap.String("email", user.name),
							zap.String("sub", user.id),
							zap.String("expired_on", user.expiresAt.String()),
						)

						next.ServeHTTP(wrt, req.WithContext(r.redirectToAuthorization(wrt, req)))
						return
					}

					scope.Logger.Info(
						"accces token for user has expired, attemping to refresh the token",
						zap.String("client_ip", clientIP),
						zap.String("email", user.email),
						zap.String("sub", user.id),
					)

					// step: check if the user has refresh token
					refresh, _, err := r.retrieveRefreshToken(req.WithContext(ctx), user)
					if err != nil {
						scope.Logger.Error(
							"unable to find a refresh token for user",
							zap.String("client_ip", clientIP),
							zap.String("email", user.email),
							zap.String("sub", user.id),
							zap.Error(err),
						)

						next.ServeHTTP(wrt, req.WithContext(r.redirectToAuthorization(wrt, req)))
						return
					}

					// attempt to refresh the access token, possibly with a renewed refresh token
					//
					// NOTE: atm, this does not retrieve explicit refresh token expiry from oauth2,
					// and take identity expiry instead: with keycloak, they are the same and equal to
					// "SSO session idle" keycloak setting.
					//
					// exp: expiration of the access token
					// expiresIn: expiration of the ID token
					conf := r.newOAuth2Config(r.config.RedirectionURL)

					scope.Logger.Debug(
						"Issuing refresh token request",
						zap.String("current access token", user.rawToken),
						zap.String("refresh token", refresh),
						zap.String("email", user.email),
						zap.String("sub", user.id),
					)

					_, newRawAccToken, newRefreshToken, accessExpiresAt, refreshExpiresIn, err := getRefreshedToken(conf, r.config, refresh)

					if err != nil {
						switch err {
						case apperrors.ErrRefreshTokenExpired:
							scope.Logger.Warn(
								"refresh token has expired, cannot retrieve access token",
								zap.String("client_ip", clientIP),
								zap.String("email", user.email),
								zap.String("sub", user.id),
							)

							r.clearAllCookies(req.WithContext(ctx), wrt)
						default:
							scope.Logger.Debug(
								"failed to refresh the access token",
								zap.Error(err),
								zap.String("access token", user.rawToken),
								zap.String("email", user.email),
								zap.String("sub", user.id),
							)
							scope.Logger.Error(
								"failed to refresh the access token",
								zap.Error(err),
								zap.String("email", user.email),
								zap.String("sub", user.id),
							)
						}

						next.ServeHTTP(wrt, req.WithContext(r.redirectToAuthorization(wrt, req)))
						return
					}

					scope.Logger.Debug(
						"info about tokens after refreshing",
						zap.String("new access token", newRawAccToken),
						zap.String("new refresh token", newRefreshToken),
						zap.String("email", user.email),
						zap.String("sub", user.id),
					)

					accessExpiresIn := time.Until(accessExpiresAt)

					// get the expiration of the new refresh token
					if newRefreshToken != "" {
						refresh = newRefreshToken
					}

					if refreshExpiresIn == 0 {
						// refresh token expiry claims not available: try to parse refresh token
						refreshExpiresIn = r.getAccessCookieExpiration(refresh)
					}

					scope.Logger.Info(
						"injecting the refreshed access token cookie",
						zap.String("client_ip", clientIP),
						zap.String("cookie_name", r.config.CookieAccessName),
						zap.String("email", user.email),
						zap.String("sub", user.id),
						zap.Duration("refresh_expires_in", refreshExpiresIn),
						zap.Duration("expires_in", accessExpiresIn),
					)

					accessToken := newRawAccToken

					if r.config.EnableEncryptedToken || r.config.ForceEncryptedCookie {
						if accessToken, err = encodeText(accessToken, r.config.EncryptionKey); err != nil {
							scope.Logger.Error(
								"unable to encode the access token", zap.Error(err),
								zap.String("email", user.email),
								zap.String("sub", user.id),
							)

							wrt.WriteHeader(http.StatusInternalServerError)
							return
						}
					}

					// step: inject the refreshed access token
					r.dropAccessTokenCookie(req.WithContext(ctx), wrt, accessToken, accessExpiresIn)

					// step: inject the renewed refresh token
					if newRefreshToken != "" {
						scope.Logger.Debug(
							"renew refresh cookie with new refresh token",
							zap.Duration("refresh_expires_in", refreshExpiresIn),
							zap.String("email", user.email),
							zap.String("sub", user.id),
						)

						encryptedRefreshToken, err := encodeText(newRefreshToken, r.config.EncryptionKey)

						if err != nil {
							scope.Logger.Error(
								"failed to encrypt the refresh token",
								zap.Error(err),
								zap.String("email", user.email),
								zap.String("sub", user.id),
							)

							wrt.WriteHeader(http.StatusInternalServerError)
							return
						}

						if r.useStore() {
							go func(old, new string, encrypted string) {
								if err := r.DeleteRefreshToken(old); err != nil {
									scope.Logger.Error("failed to remove old token", zap.Error(err))
								}

								if err := r.StoreRefreshToken(new, encrypted, refreshExpiresIn); err != nil {
									scope.Logger.Error("failed to store refresh token", zap.Error(err))
									return
								}
							}(user.rawToken, newRawAccToken, encryptedRefreshToken)
						} else {
							r.dropRefreshTokenCookie(req.WithContext(ctx), wrt, encryptedRefreshToken, refreshExpiresIn)
						}
					}

					// update the with the new access token and inject into the context
					user.rawToken = newRawAccToken
					ctx = context.WithValue(req.Context(), contextScopeName, scope)
				}
			}

			next.ServeHTTP(wrt, req.WithContext(ctx))
		})
	}
}

// authorizationMiddleware is responsible for verifying permissions in access_token
// nolint:funlen
func (r *oauthProxy) authorizationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			scope, assertOk := req.Context().Value(contextScopeName).(*RequestScope)

			if !assertOk {
				r.log.Error(
					"Assertion failed",
				)
				return
			}

			if scope.AccessDenied {
				next.ServeHTTP(wrt, req)
				return
			}

			user := scope.Identity
			noAuthz := false

			var decision authorization.AuthzDecision
			var err error

			if r.useStore() {
				decision, err = r.GetAuthz(user.rawToken, req.URL)
				noAuthz = err == apperrors.ErrNoAuthzFound
			}

			if !r.useStore() || noAuthz {
				r.pat.m.Lock()
				token := r.pat.Token.AccessToken
				r.pat.m.Unlock()

				provider := authorization.KeycloakAuthorizationProvider{}
				decision, err = provider.Authorize(
					user.permissions,
					req,
					r.idpClient,
					r.config.OpenIDProviderTimeout,
					token,
					r.config.Realm,
				)
			}

			switch err {
			case apperrors.ErrPermissionNotInToken:
				scope.Logger.Info(apperrors.ErrPermissionNotInToken.Error())
			case apperrors.ErrResourceRetrieve:
				scope.Logger.Info(apperrors.ErrResourceRetrieve.Error())
			case apperrors.ErrNoIDPResourceForPath:
				scope.Logger.Info(apperrors.ErrNoIDPResourceForPath.Error())
			case apperrors.ErrResourceIDNotPresent:
				scope.Logger.Info(apperrors.ErrResourceIDNotPresent.Error())
			case apperrors.ErrTokenScopeNotMatchResourceScope:
				scope.Logger.Info(apperrors.ErrTokenScopeNotMatchResourceScope.Error())
			case apperrors.ErrNoAuthzFound:
			default:
				if err != nil {
					scope.Logger.Error(
						"Undexpected error during authorization",
						zap.Error(err),
					)
					next.ServeHTTP(wrt, req.WithContext(r.revokeProxy(wrt, req)))
					return
				}
			}

			if noAuthz {
				err := r.StoreAuthz(
					user.rawToken,
					req.URL,
					decision,
					time.Until(user.expiresAt),
				)

				if err != nil {
					scope.Logger.Error(
						"problem setting authz decision to store",
						zap.Error(err),
					)
				}
			}

			if decision == authorization.DeniedAuthz {
				if !noAuthz {
					scope.Logger.Debug(
						"authz denied from cache",
						zap.String("user", user.name),
						zap.String("path", req.URL.Path),
					)
				}
				next.ServeHTTP(wrt, req.WithContext(r.redirectToAuthorization(wrt, req)))
				return
			}

			next.ServeHTTP(wrt, req)
		})
	}
}

// checkClaim checks whether claim in userContext matches claimName, match. It can be String or Strings claim.
func (r *oauthProxy) checkClaim(user *userContext, claimName string, match *regexp.Regexp, resourceURL string) bool {
	errFields := []zapcore.Field{
		zap.String("claim", claimName),
		zap.String("access", "denied"),
		zap.String("email", user.email),
		zap.String("resource", resourceURL),
	}

	if _, found := user.claims[claimName]; !found {
		r.log.Warn("the token does not have the claim", errFields...)
		return false
	}

	switch user.claims[claimName].(type) {
	case []interface{}:
		for _, v := range user.claims[claimName].([]interface{}) {
			value, ok := v.(string)

			if !ok {
				r.log.Warn(
					"Problem while asserting claim",
					append(
						errFields,
						zap.String(
							"issued",
							fmt.Sprintf("%v", user.claims[claimName]),
						),
						zap.String("required", match.String()),
					)...,
				)

				return false
			}

			if match.MatchString(value) {
				return true
			}
		}
		r.log.Warn(
			"claim requirement does not match any element claim group in token",
			append(
				errFields,
				zap.String(
					"issued",
					fmt.Sprintf("%v", user.claims[claimName]),
				),
				zap.String("required", match.String()),
			)...,
		)

		return false
	case string:
		if match.MatchString(user.claims[claimName].(string)) {
			return true
		}

		r.log.Warn(
			"claim requirement does not match claim in token",
			append(
				errFields,
				zap.String("issued", user.claims[claimName].(string)),
				zap.String("required", match.String()),
			)...,
		)

		return false
	default:
		r.log.Error(
			"unable to extract the claim from token not string or array of strings",
		)
	}

	r.log.Warn("unexpected error", errFields...)
	return false
}

// admissionMiddleware is responsible for checking the access token against the protected resource
func (r *oauthProxy) admissionMiddleware(resource *Resource) func(http.Handler) http.Handler {
	claimMatches := make(map[string]*regexp.Regexp)

	for k, v := range r.config.MatchClaims {
		claimMatches[k] = regexp.MustCompile(v)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			// we don't need to continue is a decision has been made
			scope, assertOk := req.Context().Value(contextScopeName).(*RequestScope)

			if !assertOk {
				r.log.Error(
					"Assertion failed",
				)
				return
			}

			if scope.AccessDenied {
				next.ServeHTTP(wrt, req)
				return
			}

			user := scope.Identity

			// @step: we need to check the roles
			if !hasAccess(resource.Roles, user.roles, !resource.RequireAnyRole) {
				scope.Logger.Warn("access denied, invalid roles",
					zap.String("access", "denied"),
					zap.String("email", user.email),
					zap.String("resource", resource.URL),
					zap.String("roles", resource.getRoles()))

				next.ServeHTTP(wrt, req.WithContext(r.accessForbidden(wrt, req)))
				return
			}

			// @step: check if we have any groups, the groups are there
			if !hasAccess(resource.Groups, user.groups, false) {
				scope.Logger.Warn("access denied, invalid groups",
					zap.String("access", "denied"),
					zap.String("email", user.email),
					zap.String("resource", resource.URL),
					zap.String("groups", strings.Join(resource.Groups, ",")))

				next.ServeHTTP(wrt, req.WithContext(r.accessForbidden(wrt, req)))
				return
			}

			// step: if we have any claim matching, lets validate the tokens has the claims
			for claimName, match := range claimMatches {
				if !r.checkClaim(user, claimName, match, resource.URL) {
					next.ServeHTTP(wrt, req.WithContext(r.accessForbidden(wrt, req)))
					return
				}
			}

			scope.Logger.Debug("access permitted to resource",
				zap.String("access", "permitted"),
				zap.String("email", user.email),
				zap.Duration("expires", time.Until(user.expiresAt)),
				zap.String("resource", resource.URL))

			next.ServeHTTP(wrt, req)
		})
	}
}

// responseHeaderMiddleware is responsible for adding response headers
func (r *oauthProxy) responseHeaderMiddleware(headers map[string]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			// @step: inject any custom response headers
			for k, v := range headers {
				wrt.Header().Set(k, v)
			}

			next.ServeHTTP(wrt, req)
		})
	}
}

// identityHeadersMiddleware is responsible for adding the authentication headers to upstream
func (r *oauthProxy) identityHeadersMiddleware(custom []string) func(http.Handler) http.Handler {
	customClaims := make(map[string]string)

	const minSliceLength int = 1

	for _, val := range custom {
		xslices := strings.Split(val, "|")
		val = xslices[0]

		if len(xslices) > minSliceLength {
			customClaims[val] = toHeader(xslices[1])
		} else {
			customClaims[val] = fmt.Sprintf("X-Auth-%s", toHeader(val))
		}
	}

	cookieFilter := []string{r.config.CookieAccessName, r.config.CookieRefreshName}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			scope := req.Context().Value(contextScopeName).(*RequestScope)

			if scope.Identity != nil {
				user := scope.Identity
				req.Header.Set("X-Auth-Audience", strings.Join(user.audiences, ","))
				req.Header.Set("X-Auth-Email", user.email)
				req.Header.Set("X-Auth-ExpiresIn", user.expiresAt.String())
				req.Header.Set("X-Auth-Groups", strings.Join(user.groups, ","))
				req.Header.Set("X-Auth-Roles", strings.Join(user.roles, ","))
				req.Header.Set("X-Auth-Subject", user.id)
				req.Header.Set("X-Auth-Userid", user.name)
				req.Header.Set("X-Auth-Username", user.name)

				// should we add the token header?
				if r.config.EnableTokenHeader {
					req.Header.Set("X-Auth-Token", user.rawToken)
				}
				// add the authorization header if requested
				if r.config.EnableAuthorizationHeader {
					req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", user.rawToken))
				}
				// are we filtering out the cookies
				if !r.config.EnableAuthorizationCookies {
					_ = filterCookies(req, cookieFilter)
				}
				// inject any custom claims
				for claim, header := range customClaims {
					if claim, found := user.claims[claim]; found {
						req.Header.Set(header, fmt.Sprintf("%v", claim))
					}
				}
			}

			next.ServeHTTP(wrt, req)
		})
	}
}

// securityMiddleware performs numerous security checks on the request
func (r *oauthProxy) securityMiddleware(next http.Handler) http.Handler {
	r.log.Info("enabling the security filter middleware")

	secure := secure.New(secure.Options{
		AllowedHosts:          r.config.Hostnames,
		BrowserXssFilter:      r.config.EnableBrowserXSSFilter,
		ContentSecurityPolicy: r.config.ContentSecurityPolicy,
		ContentTypeNosniff:    r.config.EnableContentNoSniff,
		FrameDeny:             r.config.EnableFrameDeny,
		SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
		SSLRedirect:           r.config.EnableHTTPSRedirect,
	})

	return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
		scope, assertOk := req.Context().Value(contextScopeName).(*RequestScope)

		if !assertOk {
			r.log.Error(
				"Assertion failed",
			)
			return
		}

		if err := secure.Process(wrt, req); err != nil {
			scope.Logger.Warn("failed security middleware", zap.Error(err))
			next.ServeHTTP(wrt, req.WithContext(r.accessForbidden(wrt, req)))
			return
		}

		next.ServeHTTP(wrt, req)
	})
}

// methodCheck middleware
func (r *oauthProxy) methodCheckMiddleware(next http.Handler) http.Handler {
	r.log.Info("enabling the method check middleware")

	return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
		if !isValidHTTPMethod(req.Method) {
			r.log.Warn("method not implemented ", zap.String("method", req.Method))
			wrt.WriteHeader(http.StatusNotImplemented)
			return
		}

		next.ServeHTTP(wrt, req)
	})
}

// proxyDenyMiddleware just block everything
func proxyDenyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
		ctxVal := req.Context().Value(contextScopeName)

		var scope *RequestScope
		if ctxVal == nil {
			scope = &RequestScope{}
		} else {
			scope = ctxVal.(*RequestScope)
		}

		scope.AccessDenied = true
		// update the request context
		ctx := context.WithValue(req.Context(), contextScopeName, scope)

		next.ServeHTTP(wrt, req.WithContext(ctx))
	})
}

// deny middleware
func (r *oauthProxy) denyMiddleware(next http.Handler) http.Handler {
	r.log.Info("enabling the deny middleware")

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		next.ServeHTTP(w, req)
	})
}
