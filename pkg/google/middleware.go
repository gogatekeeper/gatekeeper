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
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"go.uber.org/zap"
)

/*
	authorizationMiddleware is responsible for verifying permissions in access_token/uma_token
*/
//nolint:cyclop
func authorizationMiddleware(
	logger *zap.Logger,
	enableOpa bool,
	opaTimeout time.Duration,
	opaAuthzURL *url.URL,
	accessForbidden func(wrt http.ResponseWriter, req *http.Request) context.Context,
) func(http.Handler) http.Handler {
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

			scope.Logger.Debug("authorization middleware")

			var provider authorization.Provider
			var decision authorization.AuthzDecision
			var err error

			scope.Logger.Debug("query external authz provider for authz")

			if enableOpa {
				// initially request Body is stream read from network connection,
				// when read once, it is closed, so second time we would not be able to
				// read it, so what we will do here is that we will read body,
				// create copy of original request and pass body which we already read
				// to original req and to new copy of request,
				// new copy will be passed to authorizer, which also needs to read body
				reqBody, varErr := io.ReadAll(req.Body)
				if varErr != nil {
					decision = authorization.DeniedAuthz
					err = varErr
				} else {
					req.Body.Close()
					passReq := *req
					passReq.Body = io.NopCloser(bytes.NewReader(reqBody))
					req.Body = io.NopCloser(bytes.NewReader(reqBody))

					provider = authorization.NewOpaAuthorizationProvider(
						opaTimeout,
						*opaAuthzURL,
						&passReq,
					)
					decision, err = provider.Authorize()
				}
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
					scope.Logger.Error(apperrors.ErrFailedAuthzRequest.Error(), zap.Error(err))
				}
			}

			scope.Logger.Info("authz decision", zap.String("decision", decision.String()))

			if decision == authorization.DeniedAuthz {
				accessForbidden(wrt, req)
				return
			}
			next.ServeHTTP(wrt, req)
		})
	}
}
