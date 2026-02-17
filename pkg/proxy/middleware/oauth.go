package middleware

import (
	"context"
	"errors"
	"fmt"
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

// AuthenticationMiddleware is responsible for verifying the access token
//
//nolint:funlen,cyclop
func AuthenticationMiddleware(
	logger *zap.Logger,
	cookieAccessName string,
	cookieRefreshName string,
	getIdentity func(req *http.Request, tokenCookie string, tokenHeader string) (string, error),
	httpClient *http.Client,
	enableIDPSessionCheck bool,
	provider *oidc3.Provider,
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
	enableOptionalEncryption bool,
	enableCompressToken bool,
	enableIDTokenClaims bool,
	enableUserInfoClaims bool,
	compressTokenPool *utils.LimitedBufferPool,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*models.RequestScope)
			if !assertOk {
				logger.Error(apperrors.ErrAssertionFailed.Error())
				return
			}

			scope.Logger.Debug("authentication middleware")
			lLog := scope.Logger.With(
				zap.String("remote_addr", req.RemoteAddr),
			)

			ctx := context.WithValue(req.Context(), constant.ContextScopeName, scope)
			// grab the user identity from the request
			token, err := getIdentity(req, cookieAccessName, "")
			if err != nil {
				scope.Logger.Error(err.Error())
				core.RevokeProxy(logger, req)
				next.ServeHTTP(wrt, req)

				return
			}

			// IMPORTANT: For all calls with go-oidc library be aware
			// that calls accept context parameter and you have to pass
			// client from provider through this parameter, although
			// provider is already configured with client!!!
			// https://github.com/coreos/go-oidc/issues/402
			oidcLibCtx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)

			idToken := ""

			if enableIDTokenClaims {
				var idErr error

				idToken, idErr = getIdentity(req, cookMgr.CookieIDTokenName, "")
				if idErr != nil {
					scope.Logger.Error(idErr.Error())
					core.RevokeProxy(logger, req)
					next.ServeHTTP(wrt, req)

					return
				}

				_, _, err = utils.VerifyOIDCTokens(
					req.Context(),
					provider,
					clientID,
					token,
					idToken,
					skipAccessTokenClientIDCheck,
					skipAccessTokenIssuerCheck,
				)
			} else {
				_, err = utils.VerifyToken(
					ctx,
					provider,
					token,
					clientID,
					skipAccessTokenClientIDCheck,
					skipAccessTokenIssuerCheck,
				)
			}

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

				user, err := session.ExtractIdentity(token)
				if err != nil {
					lLog.Error(err.Error())
					core.RevokeProxy(logger, req)
					next.ServeHTTP(wrt, req)

					return
				}

				logger.Debug("found the user identity",
					zap.String("id", user.ID),
					zap.String("name", user.Name),
					zap.String("email", user.Email),
					zap.String("roles", strings.Join(user.Roles, ",")),
					zap.String("groups", strings.Join(user.Groups, ",")))

				lLog.Info("accces token for user has expired, attemping to refresh the token")

				// step: check if the user has refresh token
				refresh, _, err := session.RetrieveRefreshToken(
					store,
					cookieRefreshName,
					encryptionKey,
					req.WithContext(ctx),
					user,
					enableOptionalEncryption,
					enableCompressToken,
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

				if encryptionKey != "" {
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
				}

				scope.Identity = user

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

				_, newRawAccToken, newRefreshToken, accessExpiresAt, refreshExpiresIn, err := utils.GetRefreshedToken(
					ctx,
					conf,
					httpClient,
					refresh,
				)
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
				// update the with the new access token and inject into the context
				newUser, err := session.ExtractIdentity(accessToken)
				if err != nil {
					lLog.Error(err.Error())
					accessForbidden(wrt, req)

					return
				}

				if enableEncryptedToken || forceEncryptedCookie {
					if enableCompressToken {
						accessToken, err = session.EncryptAndCompressToken(accessToken, encryptionKey, compressTokenPool)
						if err != nil {
							lLog.Error(
								apperrors.ErrEncryptAndCompressAccToken.Error(),
								zap.Error(err),
							)
							accessForbidden(wrt, req)

							return
						}
					} else {
						accessToken, err = encryption.EncodeText(accessToken, encryptionKey)
						if err != nil {
							lLog.Error(
								apperrors.ErrEncryptAccToken.Error(),
								zap.Error(err),
							)
							accessForbidden(wrt, req)

							return
						}
					}
				}

				// step: inject the refreshed access token
				cookMgr.DropAccessTokenCookie(req.WithContext(ctx), wrt, accessToken, accessExpiresIn)

				// step: inject the renewed refresh token
				if newRefreshToken != "" {
					lLog.Debug(
						"renew refresh cookie with new refresh token",
						zap.Duration("refresh_expires_in", refreshExpiresIn),
					)

					var encryptedRefreshToken string

					if enableCompressToken {
						encryptedRefreshToken, err = session.EncryptAndCompressToken(newRefreshToken, encryptionKey, compressTokenPool)
						if err != nil {
							lLog.Error(
								apperrors.ErrEncryptRefreshToken.Error(),
								zap.Error(err),
							)
							wrt.WriteHeader(http.StatusInternalServerError)

							return
						}
					} else {
						encryptedRefreshToken, err = encryption.EncodeText(newRefreshToken, encryptionKey)
						if err != nil {
							lLog.Error(
								apperrors.ErrEncryptRefreshToken.Error(),
								zap.Error(err),
							)
							wrt.WriteHeader(http.StatusInternalServerError)

							return
						}
					}

					if store != nil {
						go func(ctx context.Context, id string, newID string, encrypted string) {
							ctxx, cancel := context.WithCancel(ctx)
							defer cancel()

							err = store.Delete(ctxx, id)
							if err != nil {
								lLog.Error(
									apperrors.ErrDelTokFromStore.Error(),
									zap.Error(err),
								)
							}

							err = store.Set(ctxx, newID, encrypted, refreshExpiresIn)
							if err != nil {
								lLog.Error(
									apperrors.ErrSaveTokToStore.Error(),
									zap.Error(err),
								)

								return
							}
						}(ctx, user.ID, newUser.ID, encryptedRefreshToken)
					} else {
						cookMgr.DropRefreshTokenCookie(req.WithContext(ctx), wrt, encryptedRefreshToken, refreshExpiresIn)
					}
				}

				if enableIDTokenClaims {
					idTokenClaims, err := session.ExtractClaims(idToken)
					if err != nil {
						lLog.Error(err.Error())
						core.RevokeProxy(logger, req)
						next.ServeHTTP(wrt, req)

						return
					}

					newUser.IDTokenClaims = idTokenClaims
				}

				// IMPORTANT: on this rely other middlewares, must be refreshed
				// with new identity!
				newUser.RawToken = newRawAccToken
				scope.Identity = newUser
				ctx = context.WithValue(req.Context(), constant.ContextScopeName, scope)
			} else {
				user, err := session.ExtractIdentity(token)
				if err != nil {
					lLog.Error(err.Error())
					core.RevokeProxy(logger, req)
					next.ServeHTTP(wrt, req)

					return
				}

				logger.Debug("found the user identity",
					zap.String("id", user.ID),
					zap.String("name", user.Name),
					zap.String("email", user.Email),
					zap.String("roles", strings.Join(user.Roles, ",")),
					zap.String("groups", strings.Join(user.Groups, ",")))

				if enableIDTokenClaims {
					idTokenClaims, err := session.ExtractClaims(idToken)
					if err != nil {
						lLog.Error(err.Error())
						core.RevokeProxy(logger, req)
						next.ServeHTTP(wrt, req)

						return
					}

					user.IDTokenClaims = idTokenClaims
				}

				scope.Identity = user
			}

			if enableIDPSessionCheck || enableUserInfoClaims {
				tokenSource := oauth2.StaticTokenSource(
					&oauth2.Token{AccessToken: scope.Identity.RawToken},
				)

				userInfo, err := provider.UserInfo(oidcLibCtx, tokenSource)
				if err != nil {
					scope.Logger.Error(err.Error())
					core.RevokeProxy(logger, req)
					next.ServeHTTP(wrt, req)

					return
				}

				if enableUserInfoClaims {
					claims := map[string]any{}

					err = userInfo.Claims(&claims)
					if err != nil {
						scope.Logger.Error(err.Error())
						core.RevokeProxy(logger, req)
						next.ServeHTTP(wrt, req)

						return
					}

					scope.Identity.UserInfoClaims = claims
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
	noProxy bool,
	baseURI string,
	oAuthURI string,
	allowedQueryParams map[string]string,
	defaultAllowedQueryParams map[string]string,
	enableXForwardedHeaders bool,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
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

				url := utils.WithOAuthURI(baseURI, oAuthURI)(constant.AuthorizationURL + authQuery)

				if noProxy || enableXForwardedHeaders {
					xForwardedHost := req.Header.Get(constant.HeaderXForwardedHost)
					xProto := req.Header.Get(constant.HeaderXForwardedProto)

					if xForwardedHost == "" || xProto == "" {
						logger.Error(apperrors.ErrMissingXForwardedHeaders.Error())

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

// NoRedirectToAuthorizationMiddleware stops request after faild authentication, in no-redirects=true mode.
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

			if scope.AccessDenied {
				wrt.WriteHeader(http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(wrt, req)
		})
	}
}
