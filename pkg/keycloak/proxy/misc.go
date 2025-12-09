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
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	configcore "github.com/gogatekeeper/gatekeeper/pkg/config/core"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	keycloak_client "github.com/gogatekeeper/gatekeeper/pkg/keycloak/client"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/session"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
)

func getPAT(
	ctx context.Context,
	clientSecret string,
	openIDProviderTimeout time.Duration,
	grantType string,
	idpClient *keycloak_client.Client,
	forwardingUsername string,
	forwardingPassword string,
) (*models.TokenResponse, *jwt.Claims, error) {
	cntx, cancel := context.WithTimeout(
		ctx,
		openIDProviderTimeout,
	)
	defer cancel()

	var (
		token *models.TokenResponse
		err   error
	)

	switch grantType {
	case configcore.GrantTypeClientCreds:
		token, err = idpClient.Login(cntx, &clientSecret, nil, nil, grantType)
	case configcore.GrantTypeUserCreds:
		token, err = idpClient.Login(
			cntx,
			&clientSecret,
			&forwardingUsername,
			&forwardingPassword,
			grantType,
		)
	default:
		return nil, nil, apperrors.ErrInvalidGrantType
	}

	if err != nil {
		return nil, nil, err
	}

	parsedToken, err := jwt.ParseSigned(token.AccessToken, constant.SignatureAlgs[:])
	if err != nil {
		return nil, nil, err
	}

	stdClaims := &jwt.Claims{}

	err = parsedToken.UnsafeClaimsWithoutVerification(stdClaims)
	if err != nil {
		return nil, nil, err
	}

	return token, stdClaims, err
}

func refreshPAT(
	ctx context.Context,
	logger *zap.Logger,
	pat *PAT,
	clientSecret string,
	openIDProviderTimeout time.Duration,
	patRetryCount int,
	patRetryInterval time.Duration,
	enableForwarding bool,
	enableSigning bool,
	forwardingGrantType string,
	idpClient *keycloak_client.Client,
	forwardingUsername string,
	forwardingPassword string,
	done chan bool,
) error {
	initialized := false
	grantType := configcore.GrantTypeClientCreds

	if (enableForwarding || enableSigning) && forwardingGrantType == configcore.GrantTypeUserCreds {
		grantType = configcore.GrantTypeUserCreds
	}

	for {
		var (
			token  *models.TokenResponse
			claims *jwt.Claims
		)

		operation := func() (string, error) {
			var err error

			pCtx, cancel := context.WithCancel(ctx)
			defer cancel()

			token, claims, err = getPAT(
				pCtx,
				clientSecret,
				openIDProviderTimeout,
				grantType,
				idpClient,
				forwardingUsername,
				forwardingPassword,
			)

			return "", err
		}

		notify := func(err error, delay time.Duration) {
			logger.Error(
				err.Error(),
				zap.Duration("retry after", delay),
			)
		}

		retryType := backoff.WithBackOff(backoff.NewConstantBackOff(patRetryInterval))
		//nolint:gosec
		countOption := backoff.WithMaxTries(uint(patRetryCount))
		notifyOption := backoff.WithNotify(notify)

		boCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		_, err := backoff.Retry(boCtx, operation, retryType, countOption, notifyOption)
		if err != nil {
			return err
		}

		pat.m.Lock()
		pat.Token = token
		pat.m.Unlock()

		if !initialized {
			done <- true
			initialized = true //nolint:wsl_v5
		}

		expiration := claims.Expiry.Time()
		refreshIn := utils.GetWithin(expiration, constant.PATRefreshInPercent)

		logger.Info(
			"waiting for access token expiration",
			zap.Float64("refresh_in", refreshIn.Seconds()),
		)

		refreshTimer := time.NewTimer(refreshIn)
		select {
		case <-ctx.Done():
			logger.Info("shutdown PAT refresh routine")
			refreshTimer.Stop()
			return nil //nolint:wsl_v5
		case <-refreshTimer.C:
		}
	}
}

func WithUMAIdentity(
	req *http.Request,
	targetPath string,
	user *models.UserContext,
	cookieUMAName string,
	provider *oidc3.Provider,
	clientID string,
	skipClientIDCheck bool,
	skipIssuerCheck bool,
	getIdentity func(req *http.Request, tokenCookie string, tokenHeader string) (string, error),
	authzFunc func(targetPath string, userPerms models.Permissions) (authorization.AuthzDecision, error),
) (authorization.AuthzDecision, error) {
	token, err := getIdentity(req, cookieUMAName, constant.UMAHeader)
	if err != nil {
		return authorization.DeniedAuthz, err
	}

	_, err = utils.VerifyToken(
		req.Context(),
		provider,
		token,
		clientID,
		skipClientIDCheck,
		skipIssuerCheck,
	)
	if err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			return authorization.DeniedAuthz, apperrors.ErrUMATokenExpired
		}
		return authorization.DeniedAuthz, err //nolint:wsl_v5
	}

	umaUser, err := session.ExtractIdentity(token)
	if err != nil {
		return authorization.DeniedAuthz, err
	}

	// make sure somebody doesn't sent one user access token
	// and others user valid uma token in one request
	if umaUser.ID != user.ID {
		return authorization.DeniedAuthz, apperrors.ErrAccessMismatchUmaToken
	}

	return authzFunc(targetPath, umaUser.Permissions)
}

// getRPT retrieves relaying party token.
func getRPT(
	ctx context.Context,
	pat *PAT,
	idpClient *keycloak_client.Client,
	targetPath string,
	userToken string,
	methodScope *string,
) (string, error) {
	pat.m.RLock()
	patTok := pat.Token.AccessToken
	pat.m.RUnlock()

	resources, err := idpClient.GetResources(
		ctx,
		patTok,
		targetPath,
		methodScope,
	)
	if err != nil {
		return "", fmt.Errorf(
			"%w %w",
			apperrors.ErrNoIDPResourceForPath,
			err,
		)
	}

	if len(resources) == 0 {
		return "", apperrors.ErrNoIDPResourceForPath
	}

	if len(resources) > 1 {
		return "", apperrors.ErrTooManyResources
	}

	resourceID := resources[0].ID
	resourceScopes := make([]string, 0)

	if len(*resources[0].ResourceScopes) == 0 {
		return "", fmt.Errorf(
			"%w, resource: %s",
			apperrors.ErrMissingScopesForResource,
			*resourceID,
		)
	}

	if methodScope != nil {
		resourceScopes = append(resourceScopes, *methodScope)
	} else {
		for _, scope := range *resources[0].ResourceScopes {
			resourceScopes = append(resourceScopes, *scope.Name)
		}
	}

	permTicket, err := idpClient.CreatePermissionTicket(
		ctx,
		patTok,
		*resourceID,
		resourceScopes,
	)
	if err != nil {
		return "", fmt.Errorf(
			"%s resource: %s %w",
			apperrors.ErrPermissionTicketForResourceID.Error(),
			*resourceID,
			err,
		)
	}

	grantType := configcore.GrantTypeUmaTicket

	if userToken == "" {
		userToken = patTok
	}

	rpt, err := idpClient.GetRequestingPartyToken(ctx, userToken, permTicket, grantType)
	if err != nil {
		return "", fmt.Errorf(
			"%s resource: %s %w",
			apperrors.ErrRetrieveRPT.Error(),
			*resourceID,
			err,
		)
	}

	return rpt, nil
}

func refreshUmaToken(
	ctx context.Context,
	pat *PAT,
	idpClient *keycloak_client.Client,
	targetPath string,
	user *models.UserContext,
	methodScope *string,
) (*models.UserContext, error) {
	tok, err := getRPT(
		ctx,
		pat,
		idpClient,
		targetPath,
		user.RawToken,
		methodScope,
	)
	if err != nil {
		return nil, err
	}

	umaUser, err := session.ExtractIdentity(tok)
	if err != nil {
		return nil, err
	}

	return umaUser, nil
}
