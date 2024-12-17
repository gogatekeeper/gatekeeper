package core

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/cookie"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
)

// RedirectToURL redirects the user and aborts the context.
func RedirectToURL(
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

// RedirectToAuthorization redirects the user to authorization handler
//
//nolint:cyclop
func RedirectToAuthorization(
	logger *zap.Logger,
	noRedirects bool,
	cookManager *cookie.Manager,
	skipTokenVerification bool,
	noProxy bool,
	baseURI string,
	oAuthURI string,
	allowedQueryParams map[string]string,
	defaultAllowedQueryParams map[string]string,
) func(wrt http.ResponseWriter, req *http.Request) context.Context {
	return func(wrt http.ResponseWriter, req *http.Request) context.Context {
		if noRedirects {
			wrt.WriteHeader(http.StatusUnauthorized)
			return revokeProxy(logger, req)
		}

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
							return revokeProxy(logger, req)
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
			return revokeProxy(logger, req)
		}

		url := utils.WithOAuthURI(baseURI, oAuthURI)(constant.AuthorizationURL + authQuery)

		if noProxy && !noRedirects {
			xForwardedHost := req.Header.Get(constant.HeaderXForwardedHost)
			xProto := req.Header.Get(constant.HeaderXForwardedProto)

			if xForwardedHost == "" || xProto == "" {
				logger.Error(apperrors.ErrForwardAuthMissingHeaders.Error())

				wrt.WriteHeader(http.StatusForbidden)
				return revokeProxy(logger, req)
			}

			url = fmt.Sprintf(
				"%s://%s%s",
				xProto,
				xForwardedHost,
				url,
			)
		}

		logger.Debug("redirecting to url", zap.String("url", url))

		RedirectToURL(
			logger,
			url,
			wrt,
			req,
			http.StatusSeeOther,
		)

		return revokeProxy(logger, req)
	}
}

func EncryptToken(
	scope *models.RequestScope,
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

// revokeProxy is responsible for stopping middleware from proxying the request.
func revokeProxy(logger *zap.Logger, req *http.Request) context.Context {
	var scope *models.RequestScope
	ctxVal := req.Context().Value(constant.ContextScopeName)

	switch ctxVal {
	case nil:
		scope = &models.RequestScope{AccessDenied: true}
	default:
		var assertOk bool
		scope, assertOk = ctxVal.(*models.RequestScope)
		if !assertOk {
			logger.Error(apperrors.ErrAssertionFailed.Error())
			scope = &models.RequestScope{AccessDenied: true}
		}
	}

	scope.AccessDenied = true

	return context.WithValue(req.Context(), constant.ContextScopeName, scope)
}
