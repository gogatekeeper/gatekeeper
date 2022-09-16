//go:build !e2e
// +build !e2e

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
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestNewKeycloakProxy(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	authConfig := &fakeAuthConfig{}
	authConfig.EnableTLS = false

	cfg.DiscoveryURL = newFakeAuthServer(authConfig).getLocation()
	cfg.Listen = "127.0.0.1:0"
	cfg.ListenHTTP = ""

	proxy, err := newProxy(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, proxy)
	assert.NotNil(t, proxy.config)
	assert.NotNil(t, proxy.router)
	assert.NotNil(t, proxy.endpoint)
	assert.NoError(t, proxy.Run())
}

func TestReverseProxyHeaders(t *testing.T) {
	proxy := newFakeProxy(nil, &fakeAuthConfig{})
	token := newTestToken(proxy.idp.getLocation())
	token.addRealmRoles([]string{fakeAdminRole})
	jwt, _ := token.getToken()
	uri := "/auth_all/test"
	requests := []fakeRequest{
		{
			URI:           uri,
			RawToken:      jwt,
			ExpectedProxy: true,
			ExpectedProxyHeaders: map[string]string{
				"X-Auth-Email":    "gambol99@gmail.com",
				"X-Auth-Roles":    "role:admin,defaultclient:default",
				"X-Auth-Subject":  token.claims.Sub,
				"X-Auth-Userid":   "rjayawardene",
				"X-Auth-Username": "rjayawardene",
			},
			ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
				"X-Auth-Token": func(t *testing.T, c *Config, value string) {
					assert.Equal(t, jwt, value)
					assert.False(t, checkAccessTokenEncryption(t, c, value))
				},
			},
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: `"uri":"` + uri + `"`,
		},
	}
	proxy.RunTests(t, requests)
}

func TestAuthTokenHeader(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestClearTextWithEnableEncryptedToken",
			ProxySettings: func(c *Config) {
				c.EnableRefreshTokens = true
				c.EnableEncryptedToken = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           fakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"X-Auth-Token": func(t *testing.T, c *Config, value string) {
							_, err := jwt.ParseSigned(value)
							assert.Nil(t, err, "Problem parsing X-Auth-Token")
							assert.False(t, checkAccessTokenEncryption(t, c, value))
						},
					},
				},
				{
					URI:           fakeAuthAllURL,
					ExpectedProxy: true,
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"X-Auth-Token": func(t *testing.T, c *Config, value string) {
							_, err := jwt.ParseSigned(value)
							assert.Nil(t, err, "Problem parsing X-Auth-Token")
							assert.False(t, checkAccessTokenEncryption(t, c, value))
						},
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestClearTextWithForceEncryptedCookie",
			ProxySettings: func(c *Config) {
				c.EnableEncryptedToken = false
				c.ForceEncryptedCookie = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           fakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"X-Auth-Token": func(t *testing.T, c *Config, value string) {
							_, err := jwt.ParseSigned(value)
							assert.Nil(t, err, "Problem parsing X-Auth-Token")
							assert.False(t, checkAccessTokenEncryption(t, c, value))
						},
					},
				},
				{
					URI:           fakeAuthAllURL,
					ExpectedProxy: true,
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"X-Auth-Token": func(t *testing.T, c *Config, value string) {
							_, err := jwt.ParseSigned(value)
							assert.Nil(t, err, "Problem parsing X-Auth-Token")
							assert.False(t, checkAccessTokenEncryption(t, c, value))
						},
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		cfgCopy := *cfg
		c := &cfgCopy
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{})
				// p.idp.setTokenExpiration(1000 * time.Millisecond)
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestForwardingProxy(t *testing.T) {
	server := httptest.NewServer(&fakeUpstreamService{})

	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestPasswordGrant",
			ProxySettings: func(conf *Config) {
				conf.EnableForwarding = true
				conf.ForwardingDomains = []string{}
				conf.ForwardingUsername = validUsername
				conf.ForwardingPassword = validPassword
				conf.ForwardingGrantType = GrantTypeUserCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
				conf.OpenIDProviderTimeout = 30 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     server.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "Bearer ey",
				},
			},
		},
		{
			Name: "TestPasswordGrantWithRefreshing",
			ProxySettings: func(conf *Config) {
				conf.EnableForwarding = true
				conf.ForwardingDomains = []string{}
				conf.ForwardingUsername = validUsername
				conf.ForwardingPassword = validPassword
				conf.ForwardingGrantType = GrantTypeUserCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     server.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					OnResponse:              delay,
					ExpectedContentContains: "Bearer ey",
				},
				{
					URL:                     server.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "Bearer ey",
				},
			},
		},
		{
			Name: "TestClientCredentialsGrant",
			ProxySettings: func(conf *Config) {
				conf.EnableForwarding = true
				conf.ForwardingDomains = []string{}
				conf.ClientID = validUsername
				conf.ClientSecret = validPassword
				conf.ForwardingGrantType = GrantTypeClientCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     server.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "Bearer ey",
				},
			},
		},
		{
			Name: "TestClientCredentialsGrantWithRefreshing",
			ProxySettings: func(conf *Config) {
				conf.EnableForwarding = true
				conf.ForwardingDomains = []string{}
				conf.ClientID = validUsername
				conf.ClientSecret = validPassword
				conf.ForwardingGrantType = GrantTypeClientCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     server.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					OnResponse:              delay,
					ExpectedContentContains: "Bearer ey",
				},
				{
					URL:                     server.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "Bearer ey",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				c := newFakeKeycloakConfig()
				c.Upstream = server.URL
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{Expiration: 900 * time.Millisecond})
				<-time.After(time.Duration(100) * time.Millisecond)
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestUmaForwardingProxy(t *testing.T) {
	fakeUpstream := httptest.NewServer(&fakeUpstreamService{})
	upstreamConfig := newFakeKeycloakConfig()
	upstreamConfig.EnableUma = true
	upstreamConfig.EnableDefaultDeny = true
	upstreamConfig.ClientID = validUsername
	upstreamConfig.ClientSecret = validPassword
	upstreamConfig.PatRetryCount = 5
	upstreamConfig.PatRetryInterval = 2 * time.Second
	upstreamConfig.Upstream = fakeUpstream.URL
	// in newFakeProxy we are creating fakeauth server so, we will
	// have two different fakeauth servers for upstream and forwarding,
	// so we need to skip issuer check, but responses will be same
	// so it is ok for this testing
	upstreamConfig.SkipAccessTokenIssuerCheck = true

	upstreamProxy := newFakeProxy(
		upstreamConfig,
		&fakeAuthConfig{},
	)

	testCases := []struct {
		Name              string
		ProxySettings     func(conf *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestFailureOnDisabledUmaOnForwardingProxy",
			ProxySettings: func(conf *Config) {
				conf.EnableForwarding = true
				conf.ForwardingDomains = []string{}
				conf.ForwardingUsername = validUsername
				conf.ForwardingPassword = validPassword
				conf.ForwardingGrantType = GrantTypeUserCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
				conf.OpenIDProviderTimeout = 30 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:           upstreamProxy.getServiceURL() + "/test",
					ProxyRequest:  true,
					ExpectedProxy: false,
					ExpectedCode:  http.StatusUnauthorized,
					ExpectedContent: func(body string, testNum int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
		{
			Name: "TestPasswordGrant",
			ProxySettings: func(conf *Config) {
				conf.EnableForwarding = true
				conf.EnableUma = true
				conf.ForwardingDomains = []string{}
				conf.ForwardingUsername = validUsername
				conf.ForwardingPassword = validPassword
				conf.ForwardingGrantType = GrantTypeUserCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
				conf.OpenIDProviderTimeout = 30 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     upstreamProxy.getServiceURL() + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "gambol",
				},
			},
		},
		{
			Name: "TestPasswordGrantWithRefreshing",
			ProxySettings: func(conf *Config) {
				conf.EnableForwarding = true
				conf.EnableUma = true
				conf.ForwardingDomains = []string{}
				conf.ForwardingUsername = validUsername
				conf.ForwardingPassword = validPassword
				conf.ForwardingGrantType = GrantTypeUserCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     upstreamProxy.getServiceURL() + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					OnResponse:              delay,
					ExpectedContentContains: "gambol",
				},
				{
					URL:                     upstreamProxy.getServiceURL() + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "gambol",
				},
			},
		},
		{
			Name: "TestClientCredentialsGrant",
			ProxySettings: func(conf *Config) {
				conf.EnableForwarding = true
				conf.EnableUma = true
				conf.ForwardingDomains = []string{}
				conf.ClientID = validUsername
				conf.ClientSecret = validPassword
				conf.ForwardingGrantType = GrantTypeClientCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     upstreamProxy.getServiceURL() + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "gambol",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				forwardingConfig := newFakeKeycloakConfig()
				forwardingConfig.Upstream = upstreamProxy.getServiceURL()

				testCase.ProxySettings(forwardingConfig)
				forwardingProxy := newFakeProxy(
					forwardingConfig,
					&fakeAuthConfig{},
				)

				// <-time.After(time.Duration(100) * time.Millisecond)
				forwardingProxy.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestSkipOpenIDProviderTLSVerifyForwardingProxy(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableForwarding = true
	cfg.PatRetryCount = 5
	cfg.PatRetryInterval = 2 * time.Second
	cfg.OpenIDProviderTimeout = 30 * time.Second
	cfg.ForwardingDomains = []string{}
	cfg.ForwardingUsername = validUsername
	cfg.ForwardingPassword = validPassword
	cfg.SkipOpenIDProviderTLSVerify = true
	cfg.ForwardingGrantType = "password"
	s := httptest.NewServer(&fakeUpstreamService{})
	requests := []fakeRequest{
		{
			URL:                     s.URL + "/test",
			ProxyRequest:            true,
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "Bearer ey",
		},
	}
	proxy := newFakeProxy(cfg, &fakeAuthConfig{EnableTLS: true})
	<-time.After(time.Duration(100) * time.Millisecond)
	proxy.RunTests(t, requests)

	cfg.SkipOpenIDProviderTLSVerify = false

	defer func() {
		if r := recover(); r != nil {
			failure, assertOk := r.(string)

			if !assertOk {
				t.Fatalf("assertion failed")
			}

			check := strings.Contains(
				failure,
				"failed to retrieve the provider configuration from discovery url",
			)
			assert.True(t, check)
		}
	}()

	proxy = newFakeProxy(cfg, &fakeAuthConfig{EnableTLS: true})
	<-time.After(time.Duration(100) * time.Millisecond)
	proxy.RunTests(t, requests)
}

func TestForbiddenTemplate(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.ForbiddenPage = "templates/forbidden.html.tmpl"
	cfg.Resources = []*authorization.Resource{
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
	}
	requests := []fakeRequest{
		{
			URI:                     "/test",
			Redirects:               false,
			HasToken:                true,
			ExpectedCode:            http.StatusForbidden,
			ExpectedContentContains: "403 Permission Denied",
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestErrorTemplate(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestErrorTemplateDisplayed",
			ProxySettings: func(c *Config) {
				c.ErrorPage = "templates/error.html.tmpl"
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                     "/oauth/callback",
					Redirects:               true,
					ExpectedCode:            http.StatusBadRequest,
					ExpectedContentContains: "400 Bad Request",
				},
			},
		},
		{
			Name: "TestWithBadErrorTemplate",
			ProxySettings: func(c *Config) {
				c.ErrorPage = "templates/error-bad-formatted.html.tmpl"
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                     "/oauth/callback",
					Redirects:               true,
					ExpectedCode:            http.StatusBadRequest,
					ExpectedContentContains: "",
				},
			},
		},
		{
			Name: "TestWithEmptyErrorTemplate",
			ProxySettings: func(c *Config) {
				c.ErrorPage = ""
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                     "/oauth/callback",
					Redirects:               true,
					ExpectedCode:            http.StatusBadRequest,
					ExpectedContentContains: "",
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		cfgCopy := *cfg
		c := &cfgCopy
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestSkipOpenIDProviderTLSVerify(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.SkipOpenIDProviderTLSVerify = true
	requests := []fakeRequest{
		{
			URI:           "/auth_all/test",
			HasLogin:      true,
			ExpectedProxy: true,
			Redirects:     true,
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{EnableTLS: true}).RunTests(t, requests)
	cfg.SkipOpenIDProviderTLSVerify = false

	defer func() {
		if r := recover(); r != nil {
			failure, assertOk := r.(string)

			if !assertOk {
				t.Fatalf("assertion failed")
			}

			check := strings.Contains(
				failure,
				"failed to retrieve the provider configuration from discovery url",
			)
			assert.True(t, check)
		}
	}()

	newFakeProxy(cfg, &fakeAuthConfig{EnableTLS: true}).RunTests(t, requests)
}

func TestOpenIDProviderProxy(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.SkipOpenIDProviderTLSVerify = true
	cfg.OpenIDProviderProxy = "http://127.0.0.1:1000"

	requests := []fakeRequest{
		{
			URI:           "/auth_all/test",
			HasLogin:      true,
			ExpectedProxy: true,
			Redirects:     true,
			ExpectedCode:  http.StatusOK,
		},
	}

	fakeAuthConf := &fakeAuthConfig{
		EnableTLS:   false,
		EnableProxy: true,
	}

	newFakeProxy(cfg, fakeAuthConf).RunTests(t, requests)

	fakeAuthConf = &fakeAuthConfig{
		EnableTLS:   false,
		EnableProxy: false,
	}

	defer func() {
		if r := recover(); r != nil {
			failure, assertOk := r.(string)

			if !assertOk {
				t.Fatalf("assertion failed")
			}

			check := strings.Contains(
				failure,
				"failed to retrieve the provider configuration from discovery url",
			)
			assert.True(t, check)
		}
	}()

	newFakeProxy(cfg, fakeAuthConf).RunTests(t, requests)
}

func TestRequestIDHeader(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableRequestID = true
	requests := []fakeRequest{
		{
			URI:           "/auth_all/test",
			HasLogin:      true,
			ExpectedProxy: true,
			Redirects:     true,
			ExpectedHeaders: map[string]string{
				"X-Request-ID": "",
			},
			ExpectedCode: http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestAuthTokenHeaderDisabled(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableTokenHeader = false
	proxy := newFakeProxy(c, &fakeAuthConfig{})
	token := newTestToken(proxy.idp.getLocation())
	jwt, _ := token.getToken()

	requests := []fakeRequest{
		{
			URI:                    "/auth_all/test",
			RawToken:               jwt,
			ExpectedNoProxyHeaders: []string{"X-Auth-Token"},
			ExpectedProxy:          true,
			ExpectedCode:           http.StatusOK,
		},
	}
	proxy.RunTests(t, requests)
}

func TestAudienceHeader(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.NoRedirects = false
	requests := []fakeRequest{
		{
			URI:           "/auth_all/test",
			HasLogin:      true,
			ExpectedProxy: true,
			Redirects:     true,
			ExpectedProxyHeaders: map[string]string{
				"X-Auth-Audience": "test",
			},
			ExpectedCode: http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestDefaultDenial(t *testing.T) {
	config := newFakeKeycloakConfig()
	config.EnableDefaultDeny = true
	config.Resources = []*authorization.Resource{
		{
			URL:         "/public/*",
			Methods:     utils.AllHTTPMethods,
			WhiteListed: true,
		},
	}
	requests := []fakeRequest{
		{
			URI:                     "/public/allowed",
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "gzip",
		},
		{
			URI:       "/not_permited",
			Redirects: false,
			ExpectedContent: func(body string, testNum int) {
				assert.Equal(t, body, "")
			},
		},
		// lowercase methods should not be valid
		{
			Method:       "get",
			URI:          "/not_permited",
			Redirects:    false,
			ExpectedCode: http.StatusNotImplemented,
			ExpectedContent: func(body string, testNum int) {
				assert.Equal(t, "", body)
			},
		},
		{
			Method:       "get",
			URI:          "/not_permited",
			Redirects:    true,
			ExpectedCode: http.StatusNotImplemented,
			ExpectedContent: func(body string, testNum int) {
				assert.Equal(t, "", body)
			},
		},
		// any "crap" methods should not be valid
		{
			Method:       "whAS9023",
			URI:          "/not_permited",
			Redirects:    false,
			ExpectedCode: http.StatusNotImplemented,
			ExpectedContent: func(body string, testNum int) {
				assert.Equal(t, "", body)
			},
		},
		{
			Method:        "whAS9023",
			URI:           "/permited_with_valid_token",
			HasToken:      true,
			ProxyRequest:  true,
			ExpectedProxy: false,
			Redirects:     false,
			ExpectedCode:  http.StatusNotImplemented,
			ExpectedContent: func(body string, testNum int) {
				assert.Equal(t, "", body)
			},
		},
		{
			Method:        "GET",
			URI:           "/permited_with_valid_token",
			HasToken:      true,
			ProxyRequest:  true,
			ExpectedProxy: true,
			Redirects:     false,
			ExpectedCode:  http.StatusOK,
			ExpectedContent: func(body string, testNum int) {
				assert.Contains(t, body, "gzip")
			},
		},
	}
	newFakeProxy(config, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestDefaultDenialStrict(t *testing.T) {
	config := newFakeKeycloakConfig()
	config.EnableDefaultDenyStrict = true
	config.Resources = []*authorization.Resource{
		{
			URL:         "/public/*",
			Methods:     utils.AllHTTPMethods,
			WhiteListed: true,
		},
		{
			URL:     "/private",
			Methods: []string{"GET"},
		},
	}
	requests := []fakeRequest{
		{
			URI:                     "/public/allowed",
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "gzip",
		},
		{
			URI:       "/not_permited",
			Redirects: false,
			ExpectedContent: func(body string, testNum int) {
				assert.Equal(t, body, "")
			},
		},
		// lowercase methods should not be valid
		{
			Method:       "get",
			URI:          "/not_permited",
			Redirects:    false,
			ExpectedCode: http.StatusNotImplemented,
			ExpectedContent: func(body string, testNum int) {
				assert.Equal(t, "", body)
			},
		},
		// any "crap" methods should not be valid
		{
			Method:       "whAS9023",
			URI:          "/not_permited",
			Redirects:    false,
			ExpectedCode: http.StatusNotImplemented,
			ExpectedContent: func(body string, testNum int) {
				assert.Equal(t, "", body)
			},
		},
		{
			Method:        "GET",
			URI:           "/not_permited_with_valid_token",
			HasToken:      true,
			ProxyRequest:  true,
			ExpectedProxy: false,
			Redirects:     false,
			ExpectedCode:  http.StatusUnauthorized,
			ExpectedContent: func(body string, testNum int) {
				assert.Equal(t, "", body)
			},
		},
		{
			Method:        "GET",
			URI:           "/not_permited_with_valid_token",
			HasToken:      true,
			ProxyRequest:  true,
			ExpectedProxy: false,
			Redirects:     true,
			ExpectedCode:  http.StatusSeeOther,
			ExpectedContent: func(body string, testNum int) {
				assert.Equal(t, "", body)
			},
		},
		{
			Method:        "GET",
			URI:           "/private",
			HasToken:      true,
			ProxyRequest:  true,
			ExpectedProxy: true,
			Redirects:     false,
			ExpectedCode:  http.StatusOK,
			ExpectedContent: func(body string, testNum int) {
				assert.Contains(t, body, "gzip")
			},
		},
		{
			Method:        http.MethodPost,
			URI:           "/private",
			HasToken:      true,
			ProxyRequest:  true,
			ExpectedProxy: false,
			Redirects:     false,
			ExpectedCode:  http.StatusUnauthorized,
			ExpectedContent: func(body string, testNum int) {
				assert.Equal(t, "", body)
			},
		},
	}
	newFakeProxy(config, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestNoProxy(t *testing.T) {
	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestEmptyXForwarded",
			ProxySettings: func(c *Config) {
				c.EnableDefaultDenyStrict = true
				c.NoRedirects = true
				c.NoProxy = true
				c.Resources = []*authorization.Resource{
					{
						URL:         "/public/*",
						Methods:     utils.AllHTTPMethods,
						WhiteListed: true,
					},
					{
						URL:     "/private",
						Methods: []string{"GET"},
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/public/allowed",
					ExpectedProxy: false,
					ExpectedCode:  http.StatusOK,
					ExpectedContent: func(body string, testNum int) {
						assert.Equal(t, body, "")
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				c := newFakeKeycloakConfig()
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestAuthorizationTemplate(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.SignInPage = "templates/sign_in.html.tmpl"
	cfg.Resources = []*authorization.Resource{
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
	}
	requests := []fakeRequest{
		{
			URI:                     cfg.WithOAuthURI(constant.AuthorizationURL),
			Redirects:               true,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "Sign In",
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestProxyProtocol(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableProxyProtocol = true
	requests := []fakeRequest{
		{
			URI:           fakeAuthAllURL + "/test",
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedProxyHeaders: map[string]string{
				"X-Forwarded-For": "127.0.0.1",
			},
			ExpectedCode: http.StatusOK,
		},
		{
			URI:           fakeAuthAllURL + "/test",
			HasToken:      true,
			ProxyProtocol: "189.10.10.1",
			ExpectedProxy: true,
			ExpectedProxyHeaders: map[string]string{
				"X-Forwarded-For": "189.10.10.1",
			},
			ExpectedCode: http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestXForwarded(t *testing.T) {
	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestEmptyXForwarded",
			ProxySettings: func(c *Config) {
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           fakeAuthAllURL + "/test",
					HasToken:      true,
					ExpectedProxy: true,
					ExpectedProxyHeaders: map[string]string{
						"X-Forwarded-For": "127.0.0.1",
						"X-Real-IP":       "127.0.0.1",
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestXForwardedPresent",
			ProxySettings: func(c *Config) {
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           fakeAuthAllURL + "/test",
					HasToken:      true,
					ExpectedProxy: true,
					Headers: map[string]string{
						"X-Forwarded-For": "189.10.10.1",
					},
					ExpectedProxyHeaders: map[string]string{
						"X-Forwarded-For": "189.10.10.1",
						"X-Real-IP":       "189.10.10.1",
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestXRealIP",
			ProxySettings: func(c *Config) {
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           fakeAuthAllURL + "/test",
					HasToken:      true,
					ExpectedProxy: true,
					Headers: map[string]string{
						"X-Real-IP": "189.10.10.1",
					},
					ExpectedProxyHeaders: map[string]string{
						"X-Forwarded-For": "189.10.10.1",
						"X-Real-IP":       "189.10.10.1",
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				c := newFakeKeycloakConfig()
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestTokenEncryption(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableEncryptedToken = true
	cfg.EncryptionKey = "US36S5kubc4BXbfzCIKTQcTzG6lvixVv"
	requests := []fakeRequest{
		{
			URI:           "/auth_all/test",
			HasLogin:      true,
			ExpectedProxy: true,
			Redirects:     true,
			ExpectedProxyHeaders: map[string]string{
				"X-Auth-Email":    "gambol99@gmail.com",
				"X-Auth-Userid":   "rjayawardene",
				"X-Auth-Username": "rjayawardene",
				"X-Forwarded-For": "127.0.0.1",
			},
			ExpectedCode: http.StatusOK,
		},
		// the token must be encrypted
		{
			URI:          "/auth_all/test",
			HasToken:     true,
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestCustomResponseHeaders(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.ResponseHeaders = map[string]string{
		"CustomReponseHeader": "True",
	}
	proxy := newFakeProxy(c, &fakeAuthConfig{})

	requests := []fakeRequest{
		{
			URI:       "/auth_all/test",
			HasLogin:  true,
			Redirects: true,
			ExpectedHeaders: map[string]string{
				"CustomReponseHeader": "True",
			},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	proxy.RunTests(t, requests)
}

func TestSkipClientIDDisabled(t *testing.T) {
	// !!!! Before in keycloak in audience of access_token was client_id of
	// client for which was access token released, but this is not according spec
	// as access_token could be also other type not just JWT
	c := newFakeKeycloakConfig()
	proxy := newFakeProxy(c, &fakeAuthConfig{})
	// create two token, one with a bad client id
	bad := newTestToken(proxy.idp.getLocation())
	bad.claims.Aud = "bad_client_id"
	badSigned, _ := bad.getToken()
	// and the good
	good := newTestToken(proxy.idp.getLocation())
	goodSigned, _ := good.getToken()
	requests := []fakeRequest{
		{
			URI:               "/auth_all/test",
			RawToken:          goodSigned,
			ExpectedProxy:     true,
			ExpectedCode:      http.StatusOK,
			SkipClientIDCheck: false,
		},
		{
			URI:               "/auth_all/test",
			RawToken:          goodSigned,
			ExpectedProxy:     true,
			ExpectedCode:      http.StatusOK,
			SkipClientIDCheck: true,
		},
		{
			URI:               "/auth_all/test",
			RawToken:          badSigned,
			ExpectedCode:      http.StatusForbidden,
			ExpectedProxy:     false,
			SkipClientIDCheck: false,
		},
		{
			URI:               "/auth_all/test",
			RawToken:          badSigned,
			ExpectedProxy:     true,
			ExpectedCode:      http.StatusOK,
			SkipClientIDCheck: true,
		},
	}
	proxy.RunTests(t, requests)
}

func TestSkipIssuer(t *testing.T) {
	c := newFakeKeycloakConfig()
	proxy := newFakeProxy(c, &fakeAuthConfig{})
	// create two token, one with a bad client id
	bad := newTestToken(proxy.idp.getLocation())
	bad.claims.Iss = "bad_issuer"
	badSigned, _ := bad.getToken()
	// and the good
	good := newTestToken(proxy.idp.getLocation())
	goodSigned, _ := good.getToken()
	requests := []fakeRequest{
		{
			URI:             "/auth_all/test",
			RawToken:        goodSigned,
			ExpectedProxy:   true,
			ExpectedCode:    http.StatusOK,
			SkipIssuerCheck: false,
		},
		{
			URI:             "/auth_all/test",
			RawToken:        goodSigned,
			ExpectedProxy:   true,
			ExpectedCode:    http.StatusOK,
			SkipIssuerCheck: true,
		},
		{
			URI:             "/auth_all/test",
			RawToken:        badSigned,
			ExpectedCode:    http.StatusForbidden,
			ExpectedProxy:   false,
			SkipIssuerCheck: false,
		},
		{
			URI:             "/auth_all/test",
			RawToken:        badSigned,
			ExpectedProxy:   true,
			ExpectedCode:    http.StatusOK,
			SkipIssuerCheck: true,
		},
	}
	proxy.RunTests(t, requests)
}

func TestAuthTokenHeaderEnabled(t *testing.T) {
	proxy := newFakeProxy(nil, &fakeAuthConfig{})
	token := newTestToken(proxy.idp.getLocation())
	signed, _ := token.getToken()

	requests := []fakeRequest{
		{
			URI:      "/auth_all/test",
			RawToken: signed,
			ExpectedProxyHeaders: map[string]string{
				"X-Auth-Token": signed,
			},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	proxy.RunTests(t, requests)
}

func TestDisableAuthorizationCookie(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableAuthorizationCookies = false
	proxy := newFakeProxy(cfg, &fakeAuthConfig{})
	token := newTestToken(proxy.idp.getLocation())
	signed, _ := token.getToken()

	requests := []fakeRequest{
		{
			URI: "/auth_all/test",
			Cookies: []*http.Cookie{
				{Name: cfg.CookieAccessName, Value: signed},
				{Name: "mycookie", Value: "myvalue"},
			},
			HasToken:                true,
			ExpectedContentContains: "kc-access=censored; mycookie=myvalue",
			ExpectedCode:            http.StatusOK,
			ExpectedProxy:           true,
		},
	}
	proxy.RunTests(t, requests)
}

//nolint:cyclop
func TestTLS(t *testing.T) {
	testProxyAddr := "127.0.0.1:14302"
	testCases := []struct {
		Name              string
		ProxySettings     func(conf *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestProxyTLS",
			ProxySettings: func(conf *Config) {
				conf.EnableDefaultDeny = true
				conf.TLSCertificate = fmt.Sprintf(os.TempDir()+"/gateadmin_crt_%d", rand.Intn(10000))
				conf.TLSPrivateKey = fmt.Sprintf(os.TempDir()+"/gateadmin_priv_%d", rand.Intn(10000))
				conf.TLSCaCertificate = fmt.Sprintf(os.TempDir()+"/gateadmin_ca_%d", rand.Intn(10000))
				conf.Listen = testProxyAddr
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:          fmt.Sprintf("https://%s/test", testProxyAddr),
					ExpectedCode: http.StatusUnauthorized,
					RequestCA:    fakeCA,
				},
			},
		},
		{
			Name: "TestProxyTLSMatch",
			ProxySettings: func(conf *Config) {
				conf.EnableDefaultDeny = true
				conf.TLSCertificate = fmt.Sprintf(os.TempDir()+"/gateadmin_crt_%d", rand.Intn(10000))
				conf.TLSPrivateKey = fmt.Sprintf(os.TempDir()+"/gateadmin_priv_%d", rand.Intn(10000))
				conf.TLSCaCertificate = fmt.Sprintf(os.TempDir()+"/gateadmin_ca_%d", rand.Intn(10000))
				conf.Listen = testProxyAddr
				conf.TLSMinVersion = "tlsv1.0"
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:          fmt.Sprintf("https://%s/test", testProxyAddr),
					ExpectedCode: http.StatusUnauthorized,
					RequestCA:    fakeCA,
					TLSMin:       tls.VersionTLS10,
				},
			},
		},
		{
			Name: "TestProxyTLSDiffer",
			ProxySettings: func(conf *Config) {
				conf.EnableDefaultDeny = true
				conf.TLSCertificate = fmt.Sprintf(os.TempDir()+"/gateadmin_crt_%d", rand.Intn(10000))
				conf.TLSPrivateKey = fmt.Sprintf(os.TempDir()+"/gateadmin_priv_%d", rand.Intn(10000))
				conf.TLSCaCertificate = fmt.Sprintf(os.TempDir()+"/gateadmin_ca_%d", rand.Intn(10000))
				conf.Listen = testProxyAddr
				conf.TLSMinVersion = "tlsv1.2"
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:          fmt.Sprintf("https://%s/test", testProxyAddr),
					ExpectedCode: http.StatusUnauthorized,
					RequestCA:    fakeCA,
					TLSMin:       tls.VersionTLS13,
				},
			},
		},
		{
			Name: "TestProxyTLSMinNotFullfilled",
			ProxySettings: func(conf *Config) {
				conf.EnableDefaultDeny = true
				conf.TLSCertificate = fmt.Sprintf(os.TempDir()+"/gateadmin_crt_%d", rand.Intn(10000))
				conf.TLSPrivateKey = fmt.Sprintf(os.TempDir()+"/gateadmin_priv_%d", rand.Intn(10000))
				conf.TLSCaCertificate = fmt.Sprintf(os.TempDir()+"/gateadmin_ca_%d", rand.Intn(10000))
				conf.Listen = testProxyAddr
				conf.TLSMinVersion = "tlsv1.3"
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                  fmt.Sprintf("https://%s/test", testProxyAddr),
					ExpectedRequestError: "tls: protocol version not supported",
					RequestCA:            fakeCA,
					TLSMax:               tls.VersionTLS12,
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		cfg := newFakeKeycloakConfig()
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(cfg)

				certFile := ""
				privFile := ""
				caFile := ""

				if cfg.TLSCertificate != "" {
					certFile = cfg.TLSCertificate
				}

				if cfg.TLSPrivateKey != "" {
					privFile = cfg.TLSPrivateKey
				}

				if cfg.TLSCaCertificate != "" {
					caFile = cfg.TLSCaCertificate
				}

				if certFile != "" {
					fakeCertByte := []byte(fakeCert)
					err := ioutil.WriteFile(certFile, fakeCertByte, 0644)

					if err != nil {
						t.Fatalf("Problem writing certificate %s", err)
					}
					defer os.Remove(certFile)
				}

				if privFile != "" {
					fakeKeyByte := []byte(fakePrivateKey)
					err := ioutil.WriteFile(privFile, fakeKeyByte, 0644)

					if err != nil {
						t.Fatalf("Problem writing privateKey %s", err)
					}
					defer os.Remove(privFile)
				}

				if caFile != "" {
					fakeCAByte := []byte(fakeCA)
					err := ioutil.WriteFile(caFile, fakeCAByte, 0644)

					if err != nil {
						t.Fatalf("Problem writing cacertificate %s", err)
					}
					defer os.Remove(caFile)
				}

				p := newFakeProxy(cfg, &fakeAuthConfig{})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestCustomHTTPMethod(t *testing.T) {
	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestPublicAllow",
			ProxySettings: func(c *Config) {
				c.EnableDefaultDeny = true
				c.CustomHTTPMethods = []string{"PROPFIND"} // WebDav method
				c.Resources = []*authorization.Resource{
					{
						URL:         "/public/*",
						Methods:     utils.AllHTTPMethods,
						WhiteListed: true,
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                     "/public/allowed",
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "gzip",
				},
			},
		},
		{
			Name: "TestPublicAllowOnCustomHTTPMethod",
			ProxySettings: func(c *Config) {
				c.EnableDefaultDeny = true
				c.CustomHTTPMethods = []string{"PROPFIND"} // WebDav method
				c.Resources = []*authorization.Resource{
					{
						URL:         "/public/*",
						Methods:     utils.AllHTTPMethods,
						WhiteListed: true,
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					Method:                  "PROPFIND",
					URI:                     "/public/allowed",
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "gzip",
				},
			},
		},
		{
			Name: "TestDefaultDenialProtectionOnCustomHTTP",
			ProxySettings: func(c *Config) {
				c.EnableDefaultDeny = true
				c.CustomHTTPMethods = []string{"PROPFIND"} // WebDav method
			},
			ExecutionSettings: []fakeRequest{
				{
					Method:        "PROPFIND",
					URI:           "/api/test",
					ExpectedProxy: false,
					ExpectedCode:  http.StatusUnauthorized,
					ExpectedContent: func(body string, testNum int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
		{
			Name: "TestDefaultDenialPassOnCustomHTTP",
			ProxySettings: func(c *Config) {
				c.EnableDefaultDeny = true
				c.CustomHTTPMethods = []string{"PROPFIND"} // WebDav method
				c.Resources = []*authorization.Resource{
					{
						URL:     "/api/*",
						Methods: []string{http.MethodGet, http.MethodPost, http.MethodPut},
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					Method:                  "PROPFIND",
					URI:                     "/api/test",
					HasLogin:                true,
					Redirects:               true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "gzip",
				},
			},
		},
		{
			Name: "TestPassOnCustomHTTP",
			ProxySettings: func(c *Config) {
				c.EnableDefaultDeny = true
				c.CustomHTTPMethods = []string{"PROPFIND"} // WebDav method
				c.Resources = []*authorization.Resource{
					{
						URL:     "/webdav/*",
						Methods: []string{"PROPFIND"},
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					Method:                  "PROPFIND",
					URI:                     "/webdav/test",
					HasLogin:                true,
					Redirects:               true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "gzip",
				},
			},
		},
		{
			Name: "TestProtectionOnCustomHTTP",
			ProxySettings: func(c *Config) {
				c.EnableDefaultDeny = true
				c.CustomHTTPMethods = []string{"PROPFIND"} // WebDav method
				c.Resources = []*authorization.Resource{
					{
						URL:     "/webdav/*",
						Methods: []string{"PROPFIND"},
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					Method:        "PROPFIND",
					URI:           "/webdav/test",
					ExpectedProxy: false,
					ExpectedCode:  http.StatusUnauthorized,
					ExpectedContent: func(body string, testNum int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
		{
			Name: "TestProtectionOnCustomHTTPWithUnvalidRequestMethod",
			ProxySettings: func(c *Config) {
				c.EnableDefaultDeny = true
				c.CustomHTTPMethods = []string{"PROPFIND"} // WebDav method
				c.Resources = []*authorization.Resource{
					{
						URL:     "/webdav/*",
						Methods: []string{"PROPFIND"},
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					Method:        "XEWED",
					URI:           "/webdav/test",
					ExpectedProxy: false,
					ExpectedCode:  http.StatusNotImplemented,
					ExpectedContent: func(body string, testNum int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				c := newFakeKeycloakConfig()
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

//nolint:cyclop
func TestStoreAuthz(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	token := newTestToken("http://test")
	jwt, err := token.getToken()

	if err != nil {
		t.Fatal("Testing token generation failed")
	}

	redisServer, err := miniredis.Run()

	if err != nil {
		t.Fatalf("Starting redis failed %s", err)
	}

	defer redisServer.Close()

	tests := []struct {
		Name            string
		ProxySettings   func(c *Config)
		ExpectedFailure bool
	}{
		{
			Name: "TestEntryInRedis",
			ProxySettings: func(c *Config) {
				c.StoreURL = fmt.Sprintf("redis://%s", redisServer.Addr())
			},
		},
		{
			Name: "TestFailedRedis",
			ProxySettings: func(c *Config) {
				c.StoreURL = fmt.Sprintf("redis://%s", "failed:65000")
			},
			ExpectedFailure: true,
		},
	}

	for _, testCase := range tests {
		testCase := testCase
		c := *cfg
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(&c)
				fProxy := newFakeProxy(&c, &fakeAuthConfig{})

				url, err := url.Parse("http://test.com/test")

				if err != nil {
					t.Fatal("Problem parsing url")
				}

				err = fProxy.proxy.StoreAuthz(jwt, url, authorization.AllowedAuthz, 1*time.Second)

				if err != nil && !testCase.ExpectedFailure {
					t.Fatalf("error storing authz %v", err)
				}

				if !testCase.ExpectedFailure {
					url.Path += "/append"
					err = fProxy.proxy.StoreAuthz(jwt, url, authorization.AllowedAuthz, 1*time.Second)

					if err != nil {
						t.Fatalf("error storing authz %v", err)
					}

					keys := redisServer.Keys()

					if len(keys) != 2 {
						t.Fatalf("expected two keys, got %d", len(keys))
					}

					decision, err := redisServer.Get(keys[0])

					if err != nil {
						t.Fatalf("problem getting value from redis")
					}

					if decision != authorization.AllowedAuthz.String() {
						t.Fatalf("bad decision stored, expected allowed, got %v", decision)
					}
				}
			},
		)
	}
}

//nolint:cyclop
func TestGetAuthz(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	token := newTestToken("http://test")
	jwt, err := token.getToken()

	if err != nil {
		t.Fatal("Testing token generation failed")
	}

	tests := []struct {
		Name            string
		ProxySettings   func(c *Config)
		JWT             string
		ExpectedFailure bool
	}{
		{
			Name: "TestEntryInStore",
			ProxySettings: func(conf *Config) {
				redisServer, err := miniredis.Run()

				if err != nil {
					t.Fatalf("Starting redis failed %s", err)
				}

				conf.StoreURL = fmt.Sprintf("redis://%s", redisServer.Addr())
			},
			JWT: jwt,
		},
		{
			Name: "TestZeroLengthToken",
			ProxySettings: func(conf *Config) {
				redisServer, err := miniredis.Run()

				if err != nil {
					t.Fatalf("Starting redis failed %s", err)
				}

				conf.StoreURL = fmt.Sprintf("redis://%s", redisServer.Addr())
			},
			JWT:             "",
			ExpectedFailure: true,
		},
		{
			Name: "TestEmptyResponse",
			ProxySettings: func(conf *Config) {
				redisServer, err := miniredis.Run()

				if err != nil {
					t.Fatalf("Starting redis failed %s", err)
				}

				conf.StoreURL = fmt.Sprintf("redis://%s", redisServer.Addr())
			},
			JWT:             jwt,
			ExpectedFailure: true,
		},
		{
			Name: "TestFailedStore",
			ProxySettings: func(conf *Config) {
				_, err := miniredis.Run()

				if err != nil {
					t.Fatalf("Starting redis failed %s", err)
				}

				conf.StoreURL = fmt.Sprintf("redis://%s", "failed:65000")
			},
			JWT:             jwt,
			ExpectedFailure: true,
		},
	}

	for _, testCase := range tests {
		testCase := testCase
		cfg := *cfg
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(&cfg)
				fProxy := newFakeProxy(&cfg, &fakeAuthConfig{})

				url, err := url.Parse("http://test.com/test")

				if err != nil {
					t.Fatal("Problem parsing url")
				}

				if !testCase.ExpectedFailure {
					err = fProxy.proxy.StoreAuthz(testCase.JWT, url, authorization.AllowedAuthz, 1*time.Second)

					if err != nil {
						t.Fatalf("error storing authz %s", err)
					}
				}

				dec, err := fProxy.proxy.GetAuthz(testCase.JWT, url)

				if err != nil {
					if !testCase.ExpectedFailure {
						t.Fatalf("error getting authz %s", err)
					}

					if dec != authorization.DeniedAuthz {
						t.Fatalf("expected undefined authz decision, got %s", dec)
					}

					if testCase.JWT == "" && err != apperrors.ErrZeroLengthToken {
						t.Fatalf("expected error %s, got %s", apperrors.ErrZeroLengthToken, err)
					}

					if testCase.JWT != "" && err != apperrors.ErrNoAuthzFound && !strings.Contains(cfg.StoreURL, "failed") {
						t.Fatalf("expected error %s, got %s", apperrors.ErrNoAuthzFound, err)
					}
				}

				if !testCase.ExpectedFailure {
					if dec != authorization.AllowedAuthz {
						t.Fatalf("bad decision stored, expected allowed, got %s", dec)
					}
				}
			},
		)
	}
}
