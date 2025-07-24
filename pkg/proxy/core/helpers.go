package core

import (
	"context"
	"encoding/base64"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"net/http"
	"strings"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
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
	return RevokeProxy(logger, req)
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

// RevokeProxy is responsible for stopping middleware from proxying the request.
func RevokeProxy(logger *zap.Logger, req *http.Request) context.Context {
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

func CheckGITAccess(resource *authorization.Resource, req *http.Request, logger *zap.Logger) bool {
	if resource != nil {
		if resource.IsGitPath && (strings.Contains(strings.ToLower(req.UserAgent()), "git/") || strings.Contains(strings.ToLower(req.UserAgent()), "gitlab-runner")) {
			authHeader := req.Header.Get(constant.AuthorizationHeader)
			logger.Debug("Checking basic auth", zap.String("authHeader", authHeader))

			if strings.Contains(authHeader, "Basic") {
				parts := strings.Split(authHeader, " ")
				if len(parts) == 2 {
					data, err := base64.StdEncoding.DecodeString(parts[1])
					logger.Debug("Auth header decoded", zap.String("header", string(data)))
					if err == nil {
						basicAuth := strings.Split(string(data), ":")
						for _, user := range resource.GitUserToExpect {
							logger.Debug("Checking user", zap.String("user", user), zap.String("authHeader", basicAuth[0]))
							if strings.Trim(user, " ") == strings.Trim(basicAuth[0], " ") {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}
