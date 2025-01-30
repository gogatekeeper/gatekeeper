package middleware

import (
	"context"
	"errors"
	"fmt"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"net/http"
	"strings"
	"time"

	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/cookie"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/core"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/session"
	"github.com/gogatekeeper/gatekeeper/pkg/storage"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

/*
	AuthenticationMiddleware is responsible for verifying the access token
*/
//nolint:funlen,cyclop
func AuthenticationMiddleware(
	logger *zap.Logger,
	cookieAccessName string,
	cookieRefreshName string,
	getIdentity func(req *http.Request, tokenCookie string, tokenHeader string) (*models.UserContext, error),
	httpClient *http.Client,
	enableIDPSessionCheck bool,
	provider *oidc3.Provider,
	skipTokenVerification bool,
	clientID string,
	skipAccessTokenClientIDCheck bool,
	skipAccessTokenIssuerCheck bool,
	accessForbidden func(wrt http.ResponseWriter, req *http.Request) context.Context,
	enableRefreshTokens bool,
	redirectionURL string,
	cookMgr *cookie.Manager,
	enableEncryptedToken bool,
	forceEncryptedCookie bool,
	encryptionKey string,
	newOAuth2Config func(redirectionURL string) *oauth2.Config,
	store storage.Storage,
	accessTokenDuration time.Duration,
	resource *authorization.Resource,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			logger.Debug("Before checking scope")

			if core.CheckGITAccess(resource, req, logger) {
				next.ServeHTTP(wrt, req)
				return
			}

			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*models.RequestScope)
			if !assertOk {
				logger.Error(apperrors.ErrAssertionFailed.Error())
				return
			}

			scope.Logger.Debug("authentication middleware")

			// grab the user identity from the request
			user, err := getIdentity(req, cookieAccessName, "")
			if err != nil {
				scope.Logger.Error(err.Error())
				core.RevokeProxy(logger, req)
				next.ServeHTTP(wrt, req)
				return
			}

			scope.Identity = user
			ctx := context.WithValue(req.Context(), constant.ContextScopeName, scope)
			lLog := scope.Logger.With(
				zap.String("remote_addr", req.RemoteAddr),
				zap.String("sub", user.ID),
				zap.String("expired_on", user.ExpiresAt.String()),
			)

			// IMPORTANT: For all calls with go-oidc library be aware
			// that calls accept context parameter and you have to pass
			// client from provider through this parameter, although
			// provider is already configured with client!!!
			// https://github.com/coreos/go-oidc/issues/402
			oidcLibCtx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)

			// step: skip if we are running skip-token-verification
			if skipTokenVerification || user.SkipVerification {
				scope.Logger.Warn(
					"skip token verification enabled, " +
						"skipping verification - TESTING ONLY",
				)

				if user.IsExpired() && !user.SkipVerification {
					lLog.Error(apperrors.ErrSessionExpiredVerifyOff.Error())
					core.RevokeProxy(logger, req)
					next.ServeHTTP(wrt, req)
					return
				}
			} else {
				_, err := utils.VerifyToken(
					ctx,
					provider,
					user.RawToken,
					clientID,
					skipAccessTokenClientIDCheck,
					skipAccessTokenIssuerCheck,
				)
				if err != nil {
					if errors.Is(err, apperrors.ErrTokenSignature) {
						lLog.Error(
							apperrors.ErrAccTokenVerifyFailure.Error(),
							zap.Error(err),
						)
						accessForbidden(wrt, req)
						return
					}

					if !strings.Contains(err.Error(), "token is expired") {
						lLog.Error(
							apperrors.ErrAccTokenVerifyFailure.Error(),
							zap.Error(err),
						)
						accessForbidden(wrt, req)
						return
					}

					if !enableRefreshTokens {
						lLog.Error(apperrors.ErrSessionExpiredRefreshOff.Error())
						core.RevokeProxy(logger, req)
						next.ServeHTTP(wrt, req)
						return
					}

					lLog.Info("accces token for user has expired, attemping to refresh the token")

					// step: check if the user has refresh token
					refresh, _, err := session.RetrieveRefreshToken(
						store,
						cookieRefreshName,
						encryptionKey,
						req.WithContext(ctx),
						user,
					)
					if err != nil {
						scope.Logger.Error(
							apperrors.ErrRefreshTokenNotFound.Error(),
							zap.Error(err),
						)
						core.RevokeProxy(logger, req)
						next.ServeHTTP(wrt, req)
						return
					}

					var stdRefreshClaims *jwt.Claims
					stdRefreshClaims, err = utils.ParseRefreshToken(refresh)
					if err != nil {
						lLog.Error(
							apperrors.ErrParseRefreshToken.Error(),
							zap.Error(err),
						)
						accessForbidden(wrt, req)
						return
					}
					if user.ID != stdRefreshClaims.Subject {
						lLog.Error(
							apperrors.ErrAccRefreshTokenMismatch.Error(),
							zap.Error(err),
						)
						accessForbidden(wrt, req)
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
					conf := newOAuth2Config(redirectionURL)

					lLog.Debug(
						"issuing refresh token request",
						zap.String("current access token", user.RawToken),
						zap.String("refresh token", refresh),
					)

					newAccToken, newRawAccToken, newRefreshToken, accessExpiresAt, refreshExpiresIn, err := utils.GetRefreshedToken(ctx, conf, httpClient, refresh)
					if err != nil {
						switch {
						case errors.Is(err, apperrors.ErrRefreshTokenExpired):
							lLog.Warn("refresh token has expired, cannot retrieve access token")
							cookMgr.ClearAllCookies(req.WithContext(ctx), wrt)
						default:
							lLog.Debug(
								apperrors.ErrAccTokenRefreshFailure.Error(),
								zap.String("access token", user.RawToken),
							)
							lLog.Error(
								apperrors.ErrAccTokenRefreshFailure.Error(),
								zap.Error(err),
							)
						}

						core.RevokeProxy(logger, req)
						next.ServeHTTP(wrt, req)
						return
					}

					lLog.Debug(
						"info about tokens after refreshing",
						zap.String("new access token", newRawAccToken),
						zap.String("new refresh token", newRefreshToken),
					)

					accessExpiresIn := time.Until(accessExpiresAt)

					if newRefreshToken != "" {
						refresh = newRefreshToken
					}

					if refreshExpiresIn == 0 {
						// refresh token expiry claims not available: try to parse refresh token
						refreshExpiresIn = session.GetAccessCookieExpiration(lLog, accessTokenDuration, refresh)
					}

					lLog.Info(
						"injecting the refreshed access token cookie",
						zap.Duration("refresh_expires_in", refreshExpiresIn),
						zap.Duration("expires_in", accessExpiresIn),
					)

					accessToken := newRawAccToken

					if enableEncryptedToken || forceEncryptedCookie {
						if accessToken, err = encryption.EncodeText(accessToken, encryptionKey); err != nil {
							lLog.Error(
								apperrors.ErrEncryptAccToken.Error(),
								zap.Error(err),
							)
							accessForbidden(wrt, req)
							return
						}
					}

					// step: inject the refreshed access token
					cookMgr.DropAccessTokenCookie(req.WithContext(ctx), wrt, accessToken, accessExpiresIn)

					// update the with the new access token and inject into the context
					newUser, err := session.ExtractIdentity(&newAccToken)
					if err != nil {
						lLog.Error(err.Error())
						accessForbidden(wrt, req)
						return
					}

					// step: inject the renewed refresh token
					if newRefreshToken != "" {
						lLog.Debug(
							"renew refresh cookie with new refresh token",
							zap.Duration("refresh_expires_in", refreshExpiresIn),
						)
						var encryptedRefreshToken string
						encryptedRefreshToken, err = encryption.EncodeText(newRefreshToken, encryptionKey)
						if err != nil {
							lLog.Error(
								apperrors.ErrEncryptRefreshToken.Error(),
								zap.Error(err),
							)
							wrt.WriteHeader(http.StatusInternalServerError)
							return
						}

						if store != nil {
							go func(ctx context.Context, old string, newToken string, encrypted string) {
								ctxx, cancel := context.WithCancel(ctx)
								defer cancel()
								if err = store.Delete(ctxx, utils.GetHashKey(old)); err != nil {
									lLog.Error(
										apperrors.ErrDelTokFromStore.Error(),
										zap.Error(err),
									)
								}

								if err = store.Set(ctxx, utils.GetHashKey(newToken), encrypted, refreshExpiresIn); err != nil {
									lLog.Error(
										apperrors.ErrSaveTokToStore.Error(),
										zap.Error(err),
									)
									return
								}
							}(ctx, user.RawToken, newRawAccToken, encryptedRefreshToken)
						} else {
							cookMgr.DropRefreshTokenCookie(req.WithContext(ctx), wrt, encryptedRefreshToken, refreshExpiresIn)
						}
					}

					// IMPORTANT: on this rely other middlewares, must be refreshed
					// with new identity!
					newUser.RawToken = newRawAccToken
					scope.Identity = newUser
					ctx = context.WithValue(req.Context(), constant.ContextScopeName, scope)
				}
			}

			if enableIDPSessionCheck {
				tokenSource := oauth2.StaticTokenSource(
					&oauth2.Token{AccessToken: scope.Identity.RawToken},
				)
				_, err := provider.UserInfo(oidcLibCtx, tokenSource)
				if err != nil {
					scope.Logger.Error(err.Error())
					core.RevokeProxy(logger, req)
					next.ServeHTTP(wrt, req)
					return
				}
			}

			*req = *(req.WithContext(ctx))
			next.ServeHTTP(wrt, req)
		})
	}
}

// RedirectToAuthorizationMiddleware redirects the user to authorization handler
//
//nolint:cyclop
func RedirectToAuthorizationMiddleware(
	logger *zap.Logger,
	cookManager *cookie.Manager,
	skipTokenVerification bool,
	noProxy bool,
	baseURI string,
	oAuthURI string,
	allowedQueryParams map[string]string,
	defaultAllowedQueryParams map[string]string,
	resource *authorization.Resource,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {

			if core.CheckGITAccess(resource, req, logger) {
				next.ServeHTTP(wrt, req)
				return
			}

			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*models.RequestScope)
			if !assertOk {
				logger.Error(apperrors.ErrAssertionFailed.Error())
				return
			}

			scope.Logger.Debug("redirecttoauthorization middleware")

			if scope.AccessDenied {
				// step: add a state referrer to the authorization page
				uuid := cookManager.DropStateParameterCookie(req, wrt)
				authQuery := "?state=" + uuid

				if len(allowedQueryParams) > 0 {
					query := ""
					for key, val := range allowedQueryParams {
						if param := req.URL.Query().Get(key); param != "" {
							if val != "" {
								if val != param {
									wrt.WriteHeader(http.StatusForbidden)
								}
							}
							query += fmt.Sprintf("&%s=%s", key, param)
						} else {
							if val, ok := defaultAllowedQueryParams[key]; ok {
								query += fmt.Sprintf("&%s=%s", key, val)
							}
						}
					}
					authQuery += query
				}

				// step: if verification is switched off, we can't authorization
				if skipTokenVerification {
					logger.Error(
						"refusing to redirection to authorization endpoint, " +
							"skip token verification switched on",
					)

					wrt.WriteHeader(http.StatusForbidden)
					return
				}

				url := utils.WithOAuthURI(baseURI, oAuthURI)(constant.AuthorizationURL + authQuery)

				if noProxy {
					xForwardedHost := req.Header.Get(constant.HeaderXForwardedHost)
					xProto := req.Header.Get(constant.HeaderXForwardedProto)

					if xForwardedHost == "" || xProto == "" {
						logger.Error(apperrors.ErrForwardAuthMissingHeaders.Error())

						wrt.WriteHeader(http.StatusForbidden)
						return
					}

					url = fmt.Sprintf(
						"%s://%s%s",
						xProto,
						xForwardedHost,
						url,
					)
				}

				logger.Debug("redirecting to url", zap.String("url", url))

				core.RedirectToURL(
					logger,
					url,
					wrt,
					req,
					http.StatusSeeOther,
				)
			} else {
				next.ServeHTTP(wrt, req)
			}
		})
	}
}

// NoRedirectToAuthorizationMiddleware stops request after failed authentication, in no-redirects=true mode.
func NoRedirectToAuthorizationMiddleware(
	logger *zap.Logger,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*models.RequestScope)

			if !assertOk {
				logger.Error(apperrors.ErrAssertionFailed.Error())
				return
			}

			scope.Logger.Debug("noredirecttoauthorization middleware")
			/*
				if req.Header.Get(constant.AuthorizationHeader) != "" {
					logger.Debug("Found authorization header", zap.String("auth-header-value", req.Header.Get(constant.AuthorizationHeader)))
				}
				if req.Header.Get("Git-Protocol") != "" {
					logger.Debug("Request header", zap.String("request-header", req.Header.Get("Git-Protocol")))
				}
				logger.Debug("Request path", zap.String("request-path", req.URL.Path))
				logger.Debug("Request user agent", zap.String("user-agent", req.UserAgent()))
			*/
			if scope.AccessDenied {
				wrt.WriteHeader(http.StatusUnauthorized)
				return
			}

			scope.Logger.Debug("access gramted")

			next.ServeHTTP(wrt, req)
		})
	}
}
