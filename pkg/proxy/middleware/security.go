package middleware

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"github.com/unrolled/secure"
	"go.uber.org/zap"
)

// SecurityMiddleware performs numerous security checks on the request
func SecurityMiddleware(
	logger *zap.Logger,
	allowedHosts []string,
	browserXSSFilter bool,
	contentSecurityPolicy string,
	contentTypeNosniff bool,
	frameDeny bool,
	sslRedirect bool,
	accessForbidden func(wrt http.ResponseWriter, req *http.Request) context.Context,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		logger.Info("enabling the security filter middleware")

		secure := secure.New(secure.Options{
			AllowedHosts:          allowedHosts,
			BrowserXssFilter:      browserXSSFilter,
			ContentSecurityPolicy: contentSecurityPolicy,
			ContentTypeNosniff:    contentTypeNosniff,
			FrameDeny:             frameDeny,
			SSLProxyHeaders:       map[string]string{constant.HeaderXForwardedProto: "https"},
			SSLRedirect:           sslRedirect,
		})

		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*models.RequestScope)
			if !assertOk {
				logger.Error(apperrors.ErrAssertionFailed.Error())
				return
			}

			if err := secure.Process(wrt, req); err != nil {
				scope.Logger.Warn("failed security middleware", zap.Error(err))
				accessForbidden(wrt, req)
				return
			}

			next.ServeHTTP(wrt, req)
		})
	}
}

// HmacMiddleware verifies hmac
func HmacMiddleware(logger *zap.Logger, encKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*models.RequestScope)
			if !assertOk {
				logger.Error(apperrors.ErrAssertionFailed.Error())
				return
			}

			if scope.AccessDenied {
				next.ServeHTTP(wrt, req)
				return
			}

			expectedMAC := req.Header.Get(constant.HeaderXHMAC)
			if expectedMAC == "" {
				logger.Debug(apperrors.ErrHmacHeaderEmpty.Error())
				wrt.WriteHeader(http.StatusBadRequest)
				return
			}

			reqHmac, err := utils.GenerateHmac(req, encKey)
			if err != nil {
				logger.Error(err.Error())
			}

			if reqHmac != expectedMAC {
				logger.Debug(apperrors.ErrHmacMismatch.Error())
				wrt.WriteHeader(http.StatusBadRequest)
				return
			}

			next.ServeHTTP(wrt, req)
		})
	}
}

// AdmissionMiddleware is responsible for checking the access token against the protected resource
//
//nolint:cyclop
func AdmissionMiddleware(
	logger *zap.Logger,
	resource *authorization.Resource,
	matchClaims map[string]string,
	accessForbidden func(wrt http.ResponseWriter, req *http.Request) context.Context,
) func(http.Handler) http.Handler {
	claimMatches := make(map[string]*regexp.Regexp)
	for k, v := range matchClaims {
		claimMatches[k] = regexp.MustCompile(v)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			// we don't need to continue is a decision has been made
			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*models.RequestScope)
			if !assertOk {
				logger.Error(apperrors.ErrAssertionFailed.Error())
				return
			}
			if scope.AccessDenied {
				next.ServeHTTP(wrt, req)
				return
			}

			user := scope.Identity
			lLog := scope.Logger.With(
				zap.String("access", "denied"),
				zap.String("userID", user.ID),
				zap.String("resource", resource.URL),
			)

			// @step: we need to check the roles
			if !utils.HasAccess(resource.Roles, user.Roles, !resource.RequireAnyRole) {
				lLog.Warn("access denied, invalid roles",
					zap.String("roles", resource.GetRoles()))
				accessForbidden(wrt, req)
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
						lLog.Warn("access denied, invalid headers",
							zap.String("headers", resource.GetHeaders()))
						accessForbidden(wrt, req)
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
					lLog.Warn("access denied, invalid headers",
						zap.String("headers", resource.GetHeaders()))
					accessForbidden(wrt, req)
					return
				}
			}

			// @step: check if we have any groups, the groups are there
			if !utils.HasAccess(resource.Groups, user.Groups, false) {
				lLog.Warn("access denied, invalid groups",
					zap.String("groups", strings.Join(resource.Groups, ",")))
				accessForbidden(wrt, req)
				return
			}

			// step: if we have any claim matching, lets validate the tokens has the claims
			for claimName, match := range claimMatches {
				if !utils.CheckClaim(scope.Logger, user, claimName, match, resource.URL) {
					accessForbidden(wrt, req)
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
