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
	"os"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/go-resty/resty/v2"
	configcore "github.com/gogatekeeper/gatekeeper/pkg/config/core"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
)

//nolint:cyclop
func getPAT(
	logger *zap.Logger,
	pat *PAT,
	clientID string,
	clientSecret string,
	openIDProviderTimeout time.Duration,
	patRetryCount int,
	patRetryInterval time.Duration,
	enableForwarding bool,
	forwardingGrantType string,
	idpClient *resty.Client,
	forwardingUsername string,
	forwardingPassword string,
	done chan bool,
) {
	retry := 0
	initialized := false
	grantType := configcore.GrantTypeClientCreds

	if enableForwarding && forwardingGrantType == configcore.GrantTypeUserCreds {
		grantType = configcore.GrantTypeUserCreds
	}

	for {
		if retry > 0 {
			logger.Info(
				"retrying fetching PAT token",
				zap.Int("retry", retry),
			)
		}

		_, cancel := context.WithTimeout(
			context.Background(),
			openIDProviderTimeout,
		)

		var token string
		var err error

		switch grantType {
		case configcore.GrantTypeClientCreds:
		case configcore.GrantTypeUserCreds:
		default:
			logger.Error(
				"Chosen grant type is not supported",
				zap.String("grant_type", grantType),
			)
			os.Exit(11)
		}

		if err != nil {
			retry++
			logger.Error("problem getting PAT token", zap.Error(err))

			if retry >= patRetryCount {
				cancel()
				os.Exit(10)
			}

			<-time.After(patRetryInterval)
			continue
		}

		pat.m.Lock()
		pat.Token = token
		pat.m.Unlock()

		if !initialized {
			done <- true
		}

		initialized = true

		parsedToken, err := jwt.ParseSigned(token)
		if err != nil {
			retry++
			logger.Error("failed to parse the access token", zap.Error(err))
			<-time.After(patRetryInterval)
			continue
		}

		stdClaims := &jwt.Claims{}
		err = parsedToken.UnsafeClaimsWithoutVerification(stdClaims)
		if err != nil {
			retry++
			logger.Error("unable to parse access token for claims", zap.Error(err))
			<-time.After(patRetryInterval)
			continue
		}

		retry = 0
		expiration := stdClaims.Expiry.Time()
		refreshIn := utils.GetWithin(expiration, 0.85)

		logger.Info(
			"waiting for expiration of access token",
			zap.Float64("refresh_in", refreshIn.Seconds()),
		)

		<-time.After(refreshIn)
	}
}
