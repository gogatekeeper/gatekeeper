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
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	uuid "github.com/gofrs/uuid"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"

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
func (r *OauthProxy) entrypointMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
		// @step: create a context for the request
		scope := &RequestScope{}
		// Save the exact formatting of the incoming request so we can use it later
		scope.Path = req.URL.Path
		scope.RawPath = req.URL.RawPath
		scope.Logger = r.Log

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
		next.ServeHTTP(resp, req.WithContext(context.WithValue(req.Context(), constant.ContextScopeName, scope)))

		// @metric record the time taken then response code
		latencyMetric.Observe(time.Since(start).Seconds())
		statusMetric.WithLabelValues(fmt.Sprintf("%d", resp.Status()), req.Method).Inc()

		// place back the original uri for any later consumers
		req.URL.Path = scope.Path
		req.URL.RawPath = scope.RawPath
	})
}

// requestIDMiddleware is responsible for adding a request id if none found
func (r *OauthProxy) requestIDMiddleware(header string) func(http.Handler) http.Handler {
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
func (r *OauthProxy) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		resp, assertOk := w.(middleware.WrapResponseWriter)

		if !assertOk {
			r.Log.Error(
				"assertion failed",
			)
			return
		}

		scope, assertOk := req.Context().Value(constant.ContextScopeName).(*RequestScope)

		if !assertOk {
			r.Log.Error(
				"assertion failed",
			)
			return
		}

		if r.Config.Verbose {
			requestLogger := r.Log.With(
				zap.Any("headers", req.Header),
			)
			scope.Logger = requestLogger
		}

		next.ServeHTTP(resp, req)

		addr := utils.RealIP(req)

		if req.URL.Path == req.URL.RawPath || req.URL.RawPath == "" {
			scope.Logger.Info("client request",
				zap.Duration("latency", time.Since(start)),
				zap.Int("status", resp.Status()),
				zap.Int("bytes", resp.BytesWritten()),
				zap.String("client_ip", addr),
				zap.String("remote_addr", req.RemoteAddr),
				zap.String("method", req.Method),
				zap.String("path", req.URL.Path))
		} else {
			scope.Logger.Info("client request",
				zap.Duration("latency", time.Since(start)),
				zap.Int("status", resp.Status()),
				zap.Int("bytes", resp.BytesWritten()),
				zap.String("client_ip", addr),
				zap.String("remote_addr", req.RemoteAddr),
				zap.String("method", req.Method),
				zap.String("path", req.URL.Path),
				zap.String("raw path", req.URL.RawPath))
		}
	})
}

/*
	authenticationMiddleware is responsible for verifying the access token
*/
//nolint:funlen,cyclop
func (r *OauthProxy) authenticationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*RequestScope)

			if !assertOk {
				r.Log.Error(
					"assertion failed",
				)
				return
			}

			clientIP := utils.RealIP(req)

			// grab the user identity from the request
			user, err := r.GetIdentity(req)

			if err != nil {
				scope.Logger.Error(
					"no session found in request, redirecting for authorization",
					zap.Error(err),
				)

				//nolint:contextcheck
				next.ServeHTTP(wrt, req.WithContext(r.redirectToAuthorization(wrt, req)))
				return
			}

			scope.Identity = user
			ctx := context.WithValue(req.Context(), constant.ContextScopeName, scope)

			// step: skip if we are running skip-token-verification
			if r.Config.SkipTokenVerification {
				scope.Logger.Warn(
					"skip token verification enabled, " +
						"skipping verification - TESTING ONLY",
				)

				if user.IsExpired() {
					scope.Logger.Error(
						"the session has expired and verification switch off",
						zap.String("client_ip", clientIP),
						zap.String("remote_addr", req.RemoteAddr),
						zap.String("username", user.Name),
						zap.String("sub", user.ID),
						zap.String("expired_on", user.ExpiresAt.String()),
					)

					//nolint:contextcheck
					next.ServeHTTP(wrt, req.WithContext(r.redirectToAuthorization(wrt, req)))
					return
				}
			} else { //nolint:gocritic
				verifier := r.Provider.Verifier(
					&oidc3.Config{
						ClientID:          r.Config.ClientID,
						SkipClientIDCheck: r.Config.SkipAccessTokenClientIDCheck,
						SkipIssuerCheck:   r.Config.SkipAccessTokenIssuerCheck,
					},
				)

				//nolint:contextcheck
				_, err := verifier.Verify(context.Background(), user.RawToken)

				if err != nil {
					// step: if the error post verification is anything other than a token
					// expired error we immediately throw an access forbidden - as there is
					// something messed up in the token
					if !strings.Contains(err.Error(), "token is expired") {
						scope.Logger.Error(
							"access token failed verification",
							zap.String("client_ip", clientIP),
							zap.String("remote_addr", req.RemoteAddr),
							zap.Error(err),
						)

						//nolint:contextcheck
						next.ServeHTTP(wrt, req.WithContext(r.accessForbidden(wrt, req)))
						return
					}

					// step: check if we are refreshing the access tokens and if not re-auth
					if !r.Config.EnableRefreshTokens {
						scope.Logger.Error(
							"session expired and access token refreshing is disabled",
							zap.String("client_ip", clientIP),
							zap.String("remote_addr", req.RemoteAddr),
							zap.String("email", user.Name),
							zap.String("sub", user.ID),
							zap.String("expired_on", user.ExpiresAt.String()),
						)

						//nolint:contextcheck
						next.ServeHTTP(wrt, req.WithContext(r.redirectToAuthorization(wrt, req)))
						return
					}

					scope.Logger.Info(
						"accces token for user has expired, attemping to refresh the token",
						zap.String("client_ip", clientIP),
						zap.String("remote_addr", req.RemoteAddr),
						zap.String("email", user.Email),
						zap.String("sub", user.ID),
					)

					// step: check if the user has refresh token
					refresh, _, err := r.retrieveRefreshToken(req.WithContext(ctx), user)
					if err != nil {
						scope.Logger.Error(
							"unable to find a refresh token for user",
							zap.String("client_ip", clientIP),
							zap.String("remote_addr", req.RemoteAddr),
							zap.String("email", user.Email),
							zap.String("sub", user.ID),
							zap.Error(err),
						)

						//nolint:contextcheck
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
					conf := r.newOAuth2Config(r.Config.RedirectionURL)

					scope.Logger.Debug(
						"Issuing refresh token request",
						zap.String("current access token", user.RawToken),
						zap.String("refresh token", refresh),
						zap.String("email", user.Email),
						zap.String("sub", user.ID),
					)

					//nolint:contextcheck
					_, newRawAccToken, newRefreshToken, accessExpiresAt, refreshExpiresIn, err := getRefreshedToken(conf, r.Config, refresh)

					if err != nil {
						switch err {
						case apperrors.ErrRefreshTokenExpired:
							scope.Logger.Warn(
								"refresh token has expired, cannot retrieve access token",
								zap.String("client_ip", clientIP),
								zap.String("remote_addr", req.RemoteAddr),
								zap.String("email", user.Email),
								zap.String("sub", user.ID),
							)

							r.ClearAllCookies(req.WithContext(ctx), wrt)
						default:
							scope.Logger.Debug(
								"failed to refresh the access token",
								zap.Error(err),
								zap.String("access token", user.RawToken),
								zap.String("email", user.Email),
								zap.String("sub", user.ID),
							)
							scope.Logger.Error(
								"failed to refresh the access token",
								zap.Error(err),
								zap.String("email", user.Email),
								zap.String("sub", user.ID),
							)
						}

						//nolint:contextcheck
						next.ServeHTTP(wrt, req.WithContext(r.redirectToAuthorization(wrt, req)))
						return
					}

					scope.Logger.Debug(
						"info about tokens after refreshing",
						zap.String("new access token", newRawAccToken),
						zap.String("new refresh token", newRefreshToken),
						zap.String("email", user.Email),
						zap.String("sub", user.ID),
					)

					accessExpiresIn := time.Until(accessExpiresAt)

					// get the expiration of the new refresh token
					if newRefreshToken != "" {
						refresh = newRefreshToken
					}

					if refreshExpiresIn == 0 {
						// refresh token expiry claims not available: try to parse refresh token
						refreshExpiresIn = r.GetAccessCookieExpiration(refresh)
					}

					scope.Logger.Info(
						"injecting the refreshed access token cookie",
						zap.String("client_ip", clientIP),
						zap.String("remote_addr", req.RemoteAddr),
						zap.String("cookie_name", r.Config.CookieAccessName),
						zap.String("email", user.Email),
						zap.String("sub", user.ID),
						zap.Duration("refresh_expires_in", refreshExpiresIn),
						zap.Duration("expires_in", accessExpiresIn),
					)

					accessToken := newRawAccToken

					if r.Config.EnableEncryptedToken || r.Config.ForceEncryptedCookie {
						if accessToken, err = encryption.EncodeText(accessToken, r.Config.EncryptionKey); err != nil {
							scope.Logger.Error(
								"unable to encode the access token", zap.Error(err),
								zap.String("email", user.Email),
								zap.String("sub", user.ID),
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
							zap.String("email", user.Email),
							zap.String("sub", user.ID),
						)

						encryptedRefreshToken, err := encryption.EncodeText(newRefreshToken, r.Config.EncryptionKey)

						if err != nil {
							scope.Logger.Error(
								"failed to encrypt the refresh token",
								zap.Error(err),
								zap.String("email", user.Email),
								zap.String("sub", user.ID),
							)

							wrt.WriteHeader(http.StatusInternalServerError)
							return
						}

						if r.useStore() {
							go func(old, newToken string, encrypted string) {
								if err := r.DeleteRefreshToken(old); err != nil {
									scope.Logger.Error("failed to remove old token", zap.Error(err))
								}

								if err := r.StoreRefreshToken(newToken, encrypted, refreshExpiresIn); err != nil {
									scope.Logger.Error("failed to store refresh token", zap.Error(err))
									return
								}
							}(user.RawToken, newRawAccToken, encryptedRefreshToken)
						} else {
							r.DropRefreshTokenCookie(req.WithContext(ctx), wrt, encryptedRefreshToken, refreshExpiresIn)
						}
					}

					// update the with the new access token and inject into the context
					user.RawToken = newRawAccToken
					ctx = context.WithValue(req.Context(), constant.ContextScopeName, scope)
				}
			}

			next.ServeHTTP(wrt, req.WithContext(ctx))
		})
	}
}

/*
	authorizationMiddleware is responsible for verifying permissions in access_token
*/
//nolint:cyclop
func (r *OauthProxy) authorizationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*RequestScope)

			if !assertOk {
				r.Log.Error(
					"assertion failed",
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
				scope.Logger.Debug("checking if authz decision in cache")
				decision, err = r.GetAuthz(user.RawToken, req.URL)
				noAuthz = err == apperrors.ErrNoAuthzFound
			}

			decFromCache := !noAuthz && r.useStore()

			if decFromCache {
				scope.Logger.Debug("authz decision found in cache")
			}

			if !r.useStore() || noAuthz {
				var provider authorization.Provider

				scope.Logger.Debug("query external authz provider for authz")

				if r.Config.EnableUma {
					r.pat.m.Lock()
					token := r.pat.Token.AccessToken
					r.pat.m.Unlock()

					provider = authorization.NewKeycloakAuthorizationProvider(
						user.Permissions,
						req,
						r.IdpClient,
						r.Config.OpenIDProviderTimeout,
						token,
						r.Config.Realm,
					)
				} else if r.Config.EnableOpa {
					provider = authorization.NewOpaAuthorizationProvider(
						r.Config.OpaTimeout,
						*r.Config.OpaAuthzURL,
						req,
					)
				}
				decision, err = provider.Authorize()
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

					r.accessForbidden(wrt, req)
					return
				}
			}

			if noAuthz {
				scope.Logger.Debug("storing authz decision in cache")

				err := r.StoreAuthz(
					user.RawToken,
					req.URL,
					decision,
					time.Until(user.ExpiresAt),
				)

				if err != nil {
					scope.Logger.Error(
						"problem setting authz decision to store",
						zap.Error(err),
					)
				}
			}

			scope.Logger.Info(
				"authz decision",
				zap.String("decision", decision.String()),
			)

			if decision == authorization.DeniedAuthz {
				if decFromCache {
					scope.Logger.Debug(
						"authz denied from cache",
						zap.String("user", user.Name),
						zap.String("path", req.URL.Path),
					)
				}

				r.accessForbidden(wrt, req)
				return
			}

			next.ServeHTTP(wrt, req)
		})
	}
}

// checkClaim checks whether claim in userContext matches claimName, match. It can be String or Strings claim.
//
//nolint:cyclop
func (r *OauthProxy) checkClaim(user *UserContext, claimName string, match *regexp.Regexp, resourceURL string) bool {
	errFields := []zapcore.Field{
		zap.String("claim", claimName),
		zap.String("access", "denied"),
		zap.String("email", user.Email),
		zap.String("resource", resourceURL),
	}

	if _, found := user.Claims[claimName]; !found {
		r.Log.Warn("the token does not have the claim", errFields...)
		return false
	}

	switch user.Claims[claimName].(type) {
	case []interface{}:
		claims, assertOk := user.Claims[claimName].([]interface{})

		if !assertOk {
			r.Log.Error("assertion failed")
			return false
		}

		for _, v := range claims {
			value, ok := v.(string)

			if !ok {
				r.Log.Warn(
					"Problem while asserting claim",
					append(
						errFields,
						zap.String(
							"issued",
							fmt.Sprintf("%v", user.Claims[claimName]),
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

		r.Log.Warn(
			"claim requirement does not match any element claim group in token",
			append(
				errFields,
				zap.String(
					"issued",
					fmt.Sprintf("%v", user.Claims[claimName]),
				),
				zap.String("required", match.String()),
			)...,
		)

		return false
	case string:
		claims, assertOk := user.Claims[claimName].(string)

		if !assertOk {
			r.Log.Error("assertion failed")
			return false
		}

		if match.MatchString(claims) {
			return true
		}

		r.Log.Warn(
			"claim requirement does not match claim in token",
			append(
				errFields,
				zap.String("issued", claims),
				zap.String("required", match.String()),
			)...,
		)

		return false
	default:
		r.Log.Error(
			"unable to extract the claim from token not string or array of strings",
		)
	}

	r.Log.Warn("unexpected error", errFields...)
	return false
}

// admissionMiddleware is responsible for checking the access token against the protected resource
//
//nolint:cyclop
func (r *OauthProxy) admissionMiddleware(resource *authorization.Resource) func(http.Handler) http.Handler {
	claimMatches := make(map[string]*regexp.Regexp)

	for k, v := range r.Config.MatchClaims {
		claimMatches[k] = regexp.MustCompile(v)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			// we don't need to continue is a decision has been made
			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*RequestScope)

			if !assertOk {
				r.Log.Error(
					"assertion failed",
				)
				return
			}

			if scope.AccessDenied {
				next.ServeHTTP(wrt, req)
				return
			}

			user := scope.Identity

			// @step: we need to check the roles
			if !utils.HasAccess(resource.Roles, user.Roles, !resource.RequireAnyRole) {
				scope.Logger.Warn("access denied, invalid roles",
					zap.String("access", "denied"),
					zap.String("email", user.Email),
					zap.String("resource", resource.URL),
					zap.String("roles", resource.GetRoles()))

				//nolint:contextcheck
				next.ServeHTTP(wrt, req.WithContext(r.accessForbidden(wrt, req)))
				return
			}

			if len(resource.Headers) > 0 {
				var reqHeaders []string

				for _, resVal := range resource.Headers {
					resVals := strings.Split(resVal, ":")
					name := resVals[0]
					canonName := http.CanonicalHeaderKey(name)
					values, ok := req.Header[canonName]

					if !ok {
						scope.Logger.Warn("access denied, invalid headers",
							zap.String("access", "denied"),
							zap.String("email", user.Email),
							zap.String("resource", resource.URL),
							zap.String("headers", resource.GetHeaders()))

						//nolint:contextcheck
						next.ServeHTTP(wrt, req.WithContext(r.accessForbidden(wrt, req)))
						return
					}

					for _, value := range values {
						headVal := fmt.Sprintf(
							"%s:%s",
							strings.ToLower(name),
							strings.ToLower(value),
						)
						reqHeaders = append(reqHeaders, headVal)
					}
				}

				// @step: we need to check the headers
				if !utils.HasAccess(resource.Headers, reqHeaders, true) {
					scope.Logger.Warn("access denied, invalid headers",
						zap.String("access", "denied"),
						zap.String("email", user.Email),
						zap.String("resource", resource.URL),
						zap.String("headers", resource.GetHeaders()))

					//nolint:contextcheck
					next.ServeHTTP(wrt, req.WithContext(r.accessForbidden(wrt, req)))
					return
				}
			}

			// @step: check if we have any groups, the groups are there
			if !utils.HasAccess(resource.Groups, user.Groups, false) {
				scope.Logger.Warn("access denied, invalid groups",
					zap.String("access", "denied"),
					zap.String("email", user.Email),
					zap.String("resource", resource.URL),
					zap.String("groups", strings.Join(resource.Groups, ",")))

				//nolint:contextcheck
				next.ServeHTTP(wrt, req.WithContext(r.accessForbidden(wrt, req)))
				return
			}

			// step: if we have any claim matching, lets validate the tokens has the claims
			for claimName, match := range claimMatches {
				if !r.checkClaim(user, claimName, match, resource.URL) {
					//nolint:contextcheck
					next.ServeHTTP(wrt, req.WithContext(r.accessForbidden(wrt, req)))
					return
				}
			}

			scope.Logger.Debug("access permitted to resource",
				zap.String("access", "permitted"),
				zap.String("email", user.Email),
				zap.Duration("expires", time.Until(user.ExpiresAt)),
				zap.String("resource", resource.URL))

			next.ServeHTTP(wrt, req)
		})
	}
}

// responseHeaderMiddleware is responsible for adding response headers
func (r *OauthProxy) responseHeaderMiddleware(headers map[string]string) func(http.Handler) http.Handler {
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
//
//nolint:cyclop
func (r *OauthProxy) identityHeadersMiddleware(custom []string) func(http.Handler) http.Handler {
	customClaims := make(map[string]string)

	const minSliceLength int = 1

	for _, val := range custom {
		xslices := strings.Split(val, "|")
		val = xslices[0]

		if len(xslices) > minSliceLength {
			customClaims[val] = utils.ToHeader(xslices[1])
		} else {
			customClaims[val] = fmt.Sprintf("X-Auth-%s", utils.ToHeader(val))
		}
	}

	cookieFilter := []string{r.Config.CookieAccessName, r.Config.CookieRefreshName}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*RequestScope)

			if !assertOk {
				r.Log.Error(
					"assertion failed",
				)
				return
			}

			var headers http.Header
			if r.Config.NoProxy {
				headers = wrt.Header()
			} else {
				headers = req.Header
			}

			if scope.Identity != nil {
				user := scope.Identity
				headers.Set("X-Auth-Audience", strings.Join(user.Audiences, ","))
				headers.Set("X-Auth-Email", user.Email)
				headers.Set("X-Auth-ExpiresIn", user.ExpiresAt.String())
				headers.Set("X-Auth-Groups", strings.Join(user.Groups, ","))
				headers.Set("X-Auth-Roles", strings.Join(user.Roles, ","))
				headers.Set("X-Auth-Subject", user.ID)
				headers.Set("X-Auth-Userid", user.Name)
				headers.Set("X-Auth-Username", user.Name)

				// should we add the token header?
				if r.Config.EnableTokenHeader {
					headers.Set("X-Auth-Token", user.RawToken)
				}
				// add the authorization header if requested
				if r.Config.EnableAuthorizationHeader {
					headers.Set("Authorization", fmt.Sprintf("Bearer %s", user.RawToken))
				}
				// are we filtering out the cookies
				if !r.Config.EnableAuthorizationCookies {
					_ = filterCookies(req, cookieFilter)
				}
				// inject any custom claims
				for claim, header := range customClaims {
					if claim, found := user.Claims[claim]; found {
						headers.Set(header, fmt.Sprintf("%v", claim))
					}
				}
			}

			next.ServeHTTP(wrt, req)
		})
	}
}

// securityMiddleware performs numerous security checks on the request
func (r *OauthProxy) securityMiddleware(next http.Handler) http.Handler {
	r.Log.Info("enabling the security filter middleware")

	secure := secure.New(secure.Options{
		AllowedHosts:          r.Config.Hostnames,
		BrowserXssFilter:      r.Config.EnableBrowserXSSFilter,
		ContentSecurityPolicy: r.Config.ContentSecurityPolicy,
		ContentTypeNosniff:    r.Config.EnableContentNoSniff,
		FrameDeny:             r.Config.EnableFrameDeny,
		SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
		SSLRedirect:           r.Config.EnableHTTPSRedirect,
	})

	return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
		scope, assertOk := req.Context().Value(constant.ContextScopeName).(*RequestScope)

		if !assertOk {
			r.Log.Error(
				"assertion failed",
			)
			return
		}

		if err := secure.Process(wrt, req); err != nil {
			scope.Logger.Warn("failed security middleware", zap.Error(err))
			//nolint:contextcheck
			next.ServeHTTP(wrt, req.WithContext(r.accessForbidden(wrt, req)))
			return
		}

		next.ServeHTTP(wrt, req)
	})
}

// methodCheck middleware
func (r *OauthProxy) methodCheckMiddleware(next http.Handler) http.Handler {
	r.Log.Info("enabling the method check middleware")

	return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
		if !utils.IsValidHTTPMethod(req.Method) {
			r.Log.Warn("method not implemented ", zap.String("method", req.Method))
			wrt.WriteHeader(http.StatusNotImplemented)
			return
		}

		next.ServeHTTP(wrt, req)
	})
}

// proxyDenyMiddleware just block everything
func (r *OauthProxy) proxyDenyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
		ctxVal := req.Context().Value(constant.ContextScopeName)

		var scope *RequestScope
		if ctxVal == nil {
			scope = &RequestScope{}
		} else {
			var assertOk bool
			scope, assertOk = ctxVal.(*RequestScope)
			if !assertOk {
				r.Log.Error(
					"assertion failed",
				)
				return
			}
		}

		scope.AccessDenied = true
		// update the request context
		ctx := context.WithValue(req.Context(), constant.ContextScopeName, scope)

		next.ServeHTTP(wrt, req.WithContext(ctx))
	})
}

// deny middleware
func (r *OauthProxy) denyMiddleware(next http.Handler) http.Handler {
	r.Log.Info("enabling the deny middleware")

	return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
		r.accessForbidden(wrt, req)
	})
}
