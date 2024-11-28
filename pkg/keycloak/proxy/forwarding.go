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
	"net/http"

	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
)

// forwardProxyHandler is responsible for signing outbound requests
func forwardProxyHandler(
	logger *zap.Logger,
	pat *PAT,
	rpt *RPT,
	enableUma bool,
	forwardingDomains []string,
	enableHmac bool,
	encryptionKey string,
) func(*http.Request, *http.Response) {
	return func(req *http.Request, _ *http.Response) {
		var token string

		pat.m.RLock()
		token = pat.Token.AccessToken
		pat.m.RUnlock()

		if rpt != nil && enableUma {
			rpt.m.RLock()
			umaToken := rpt.Token
			rpt.m.RUnlock()
			req.Header.Set(constant.UMAHeader, umaToken)
		}

		hostname := req.Host
		req.URL.Host = hostname
		// is the host being signed?
		if len(forwardingDomains) == 0 || utils.ContainsSubString(hostname, forwardingDomains) {
			req.Header.Set(constant.AuthorizationHeader, "Bearer "+token)
			req.Header.Set("X-Forwarded-Agent", constant.Prog)
		}
		if enableHmac {
			reqHmac, err := utils.GenerateHmac(req, encryptionKey)
			if err != nil {
				logger.Error(err.Error())
			}
			req.Header.Set(constant.HeaderXHMAC, reqHmac)
		}
	}
}
