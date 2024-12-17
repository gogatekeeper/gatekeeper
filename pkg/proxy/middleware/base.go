package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	uuid "github.com/gofrs/uuid"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/cookie"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/core"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/metrics"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"

	"github.com/PuerkitoBio/purell"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"go.uber.org/zap"
)

const (
	normalizeFlags purell.NormalizationFlags = purell.FlagRemoveDotSegments | purell.FlagRemoveDuplicateSlashes
)

// entrypointMiddleware is custom filtering for incoming requests.
func EntrypointMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			// @step: create a context for the request
			scope := &models.RequestScope{}
			// Save the exact formatting of the incoming request so we can use it later
			scope.Path = req.URL.Path
			scope.RawPath = req.URL.RawPath
			scope.Logger = logger

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
			metrics.LatencyMetric.Observe(time.Since(start).Seconds())
			metrics.StatusMetric.WithLabelValues(strconv.Itoa(resp.Status()), req.Method).Inc()

			// place back the original uri for any later consumers
			req.URL.Path = scope.Path
			req.URL.RawPath = scope.RawPath
		})
	}
}

// requestIDMiddleware is responsible for adding a request id if none found.
func RequestIDMiddleware(header string) func(http.Handler) http.Handler {
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

// loggingMiddleware is a custom http logger.
func LoggingMiddleware(
	logger *zap.Logger,
	verbose bool,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			start := time.Now()
			resp, assertOk := w.(middleware.WrapResponseWriter)
			if !assertOk {
				logger.Error(apperrors.ErrAssertionFailed.Error())
				return
			}

			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*models.RequestScope)
			if !assertOk {
				logger.Error(apperrors.ErrAssertionFailed.Error())
				return
			}

			addr := utils.RealIP(req)
			if verbose {
				requestLogger := logger.With(
					zap.Any("headers", req.Header),
					zap.String("path", req.URL.Path),
					zap.String("method", req.Method),
					zap.String("client_ip", addr),
				)
				scope.Logger = requestLogger
			}

			next.ServeHTTP(resp, req)

			if req.URL.Path == req.URL.RawPath || req.URL.RawPath == "" {
				scope.Logger.Info("client request",
					zap.Duration("latency", time.Since(start)),
					zap.Int("status", resp.Status()),
					zap.Int("bytes", resp.BytesWritten()),
					zap.String("remote_addr", req.RemoteAddr),
					zap.String("method", req.Method),
					zap.String("path", req.URL.Path))
			} else {
				scope.Logger.Info("client request",
					zap.Duration("latency", time.Since(start)),
					zap.Int("status", resp.Status()),
					zap.Int("bytes", resp.BytesWritten()),
					zap.String("remote_addr", req.RemoteAddr),
					zap.String("method", req.Method),
					zap.String("path", req.URL.Path),
					zap.String("raw path", req.URL.RawPath))
			}
		})
	}
}

// ResponseHeaderMiddleware is responsible for adding response headers.
func ResponseHeaderMiddleware(headers map[string]string) func(http.Handler) http.Handler {
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

func DenyMiddleware(
	logger *zap.Logger,
	accessForbidden func(wrt http.ResponseWriter, req *http.Request) context.Context,
) func(http.Handler) http.Handler {
	return func(_ http.Handler) http.Handler {
		logger.Info("enabling the deny middleware")
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			accessForbidden(wrt, req)
		})
	}
}

// ProxyDenyMiddleware just block everything.
func ProxyDenyMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			ctxVal := req.Context().Value(constant.ContextScopeName)

			var scope *models.RequestScope
			if ctxVal == nil {
				scope = &models.RequestScope{}
			} else {
				var assertOk bool
				scope, assertOk = ctxVal.(*models.RequestScope)
				if !assertOk {
					logger.Error(apperrors.ErrAssertionFailed.Error())
					return
				}
			}

			scope.AccessDenied = true
			// update the request context
			ctx := context.WithValue(req.Context(), constant.ContextScopeName, scope)

			next.ServeHTTP(wrt, req.WithContext(ctx))
		})
	}
}

func MethodCheckMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		logger.Info("enabling the method check middleware")

		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			if !utils.IsValidHTTPMethod(req.Method) {
				logger.Warn("method not implemented ", zap.String("method", req.Method))
				wrt.WriteHeader(http.StatusNotImplemented)
				return
			}

			next.ServeHTTP(wrt, req)
		})
	}
}

// IdentityHeadersMiddleware is responsible for adding the authentication headers to upstream
//
//nolint:cyclop
func IdentityHeadersMiddleware(
	logger *zap.Logger,
	custom []string,
	cookieAccessName string,
	cookieRefreshName string,
	noProxy bool,
	enableTokenHeader bool,
	enableAuthzHeader bool,
	enableAuthzCookies bool,
) func(http.Handler) http.Handler {
	customClaims := make(map[string]string)
	const minSliceLength int = 1
	cookieFilter := []string{cookieAccessName, cookieRefreshName}

	for _, val := range custom {
		xslices := strings.Split(val, "|")
		val = xslices[0]
		if len(xslices) > minSliceLength {
			customClaims[val] = utils.ToHeader(xslices[1])
		} else {
			customClaims[val] = "X-Auth-" + utils.ToHeader(val)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*models.RequestScope)
			if !assertOk {
				logger.Error(apperrors.ErrAssertionFailed.Error())
				return
			}

			var headers http.Header
			if noProxy {
				headers = wrt.Header()
			} else {
				headers = req.Header
			}

			if scope.Identity != nil {
				user := scope.Identity
				headers.Set("X-Auth-Audience", strings.Join(user.Audiences, ","))
				headers.Set("X-Auth-Email", user.Email)
				headers.Set("X-Auth-Expiresin", user.ExpiresAt.String())
				headers.Set("X-Auth-Groups", strings.Join(user.Groups, ","))
				headers.Set("X-Auth-Roles", strings.Join(user.Roles, ","))
				headers.Set("X-Auth-Subject", user.ID)
				headers.Set("X-Auth-Userid", user.Name)
				headers.Set("X-Auth-Username", user.Name)

				// should we add the token header?
				if enableTokenHeader {
					headers.Set("X-Auth-Token", user.RawToken)
				}
				// add the authorization header if requested
				if enableAuthzHeader {
					headers.Set(constant.AuthorizationHeader, "Bearer "+user.RawToken)
				}
				// are we filtering out the cookies
				if !enableAuthzCookies {
					_ = cookie.FilterCookies(req, cookieFilter)
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

/*
	ProxyMiddleware is responsible for handles reverse proxy
	request to the upstream endpoint
*/
//nolint:cyclop
func ProxyMiddleware(
	logger *zap.Logger,
	corsOrigins []string,
	headers map[string]string,
	endpoint *url.URL,
	preserveHost bool,
	upstream core.ReverseProxy,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(wrt, req)

			// @step: retrieve the request scope
			ctxVal := req.Context().Value(constant.ContextScopeName)
			var scope *models.RequestScope
			if ctxVal != nil {
				var assertOk bool
				scope, assertOk = ctxVal.(*models.RequestScope)
				if !assertOk {
					logger.Error(apperrors.ErrAssertionFailed.Error())
					return
				}
				if scope.AccessDenied {
					return
				}
			}

			// @step: add the proxy forwarding headers
			req.Header.Set(constant.HeaderXRealIP, utils.RealIP(req))
			if xff := req.Header.Get(constant.HeaderXForwardedFor); xff == "" {
				req.Header.Set(constant.HeaderXForwardedFor, utils.RealIP(req))
			}
			if xfh := req.Header.Get(constant.HeaderXForwardedHost); xfh == "" {
				req.Header.Set(constant.HeaderXForwardedHost, req.Host)
			}

			if len(corsOrigins) > 0 {
				// if CORS is enabled by Gatekeeper, do not propagate CORS requests upstream
				req.Header.Del("Origin")
			}
			// @step: add any custom headers to the request
			for k, v := range headers {
				req.Header.Set(k, v)
			}

			// @note: by default goproxy only provides a forwarding proxy, thus all requests have to be absolute and we must update the host headers
			req.URL.Host = endpoint.Host
			req.URL.Scheme = endpoint.Scheme
			// Restore the unprocessed original path, so that we pass upstream exactly what we received
			// as the resource request.
			if scope != nil {
				req.URL.Path = scope.Path
				req.URL.RawPath = scope.RawPath
			}
			if v := req.Header.Get("Host"); v != "" {
				req.Host = v
				req.Header.Del("Host")
			} else if !preserveHost {
				req.Host = endpoint.Host
			}

			if utils.IsUpgradedConnection(req) {
				clientIP := utils.RealIP(req)
				logger.Debug("upgrading the connnection",
					zap.String("client_ip", clientIP),
					zap.String("remote_addr", req.RemoteAddr),
				)
				if err := utils.TryUpdateConnection(req, wrt, endpoint); err != nil {
					logger.Error("failed to upgrade connection", zap.Error(err))
					wrt.WriteHeader(http.StatusInternalServerError)
					return
				}
				return
			}

			upstream.ServeHTTP(wrt, req)
		})
	}
}

func ForwardAuthMiddleware(logger *zap.Logger, oAuthURI string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		logger.Info("enabling the forward-auth middleware")

		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			if !strings.Contains(req.URL.Path, oAuthURI) { // this condition is here only because of tests to work
				if forwardedPath := req.Header.Get(constant.HeaderXForwardedURI); forwardedPath != "" {
					req.URL.Path = forwardedPath
					req.URL.RawPath = forwardedPath
				}
				if forwardedMethod := req.Header.Get(constant.HeaderXForwardedMethod); forwardedMethod != "" {
					req.Method = forwardedMethod
				}
			}
			next.ServeHTTP(wrt, req)
		})
	}
}
