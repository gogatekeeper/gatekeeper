package proxy

import (
	"net/http"

	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
)

// forwardProxyHandler is responsible for signing outbound requests.
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
