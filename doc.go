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

package main

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

var (
	release  = ""
	gitsha   = "no gitsha provided"
	compiled = "0"
	version  = ""
)

var (
	certificateRotationMetric = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "proxy_certificate_rotation_total",
			Help: "The total amount of times the certificate has been rotated",
		},
	)
	oauthTokensMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_oauth_tokens_total",
			Help: "A summary of the tokens issuesd, renewed or failed logins",
		},
		[]string{"action"},
	)
	oauthLatencyMetric = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "proxy_oauth_request_latency",
			Help: "A summary of the request latancy for requests against the openid provider, in seconds",
		},
		[]string{"action"},
	)
	latencyMetric = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "proxy_request_duration",
			Help: "A summary of the http request latency for proxy requests, in seconds",
		},
	)
	statusMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_request_status_total",
			Help: "The HTTP requests partitioned by status code",
		},
		[]string{"code", "method"},
	)
)

// getVersion returns the proxy version
func getVersion() string {
	if version == "" {
		tm, err := strconv.ParseInt(compiled, 10, 64)
		if err != nil {
			return "unable to parse compiled time"
		}
		version = fmt.Sprintf("%s (git+sha: %s, built: %s)", release, gitsha, time.Unix(tm, 0).Format("02-01-2006"))
	}

	return version
}

// RequestScope is a request level context scope passed between middleware
type RequestScope struct {
	// AccessDenied indicates the request should not be proxied on
	AccessDenied bool
	// Identity is the user Identity of the request
	Identity *userContext
	// The parsed (unescaped) value of the request path
	Path string
	// Preserve the original request path: KEYCLOAK-10864, KEYCLOAK-11276, KEYCLOAK-13315
	// The exact path received in the request, if different than Path
	RawPath string
	Logger  *zap.Logger
}

// reverseProxy is a wrapper
type reverseProxy interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request)
}

// userContext holds the information extracted the token
type userContext struct {
	// the id of the user
	id string
	// the audience for the token
	audiences []string
	// whether the context is from a session cookie or authorization header
	bearerToken bool
	// the email associated to the user
	email string
	// the expiration of the access token
	expiresAt time.Time
	// groups is a collection of groups the user in in
	groups []string
	// a name of the user
	name string
	// preferredName is the name of the user
	preferredName string
	// roles is a collection of roles the users holds
	roles []string
	// rawToken
	rawToken string
	// claims
	claims map[string]interface{}
	// permissions
	permissions authorization.Permissions
}

// tokenResponse
type tokenResponse struct {
	TokenType    string  `json:"token_type"`
	AccessToken  string  `json:"access_token"`
	IDToken      string  `json:"id_token"`
	RefreshToken string  `json:"refresh_token,omitempty"`
	ExpiresIn    float64 `json:"expires_in"`
	Scope        string  `json:"scope,omitempty"`
}
