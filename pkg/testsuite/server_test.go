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

package testsuite_test

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	configcore "github.com/gogatekeeper/gatekeeper/pkg/config/core"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/keycloak/config"
	"github.com/gogatekeeper/gatekeeper/pkg/keycloak/proxy"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeycloakProxy(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	authConfig := &fakeAuthConfig{}
	authConfig.EnableTLS = false

	cfg.DiscoveryURL = newFakeAuthServer(authConfig).getLocation()
	cfg.Listen = randomLocalHost
	cfg.ListenHTTP = ""

	proxy, err := proxy.NewProxy(cfg, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, proxy)
	assert.NotNil(t, proxy.Config)
	assert.NotNil(t, proxy.Router)
	assert.NotNil(t, proxy.Endpoint)
	_, err = proxy.Run()
	require.NoError(t, err)
}

func TestNewKeycloakProxyWithLegacyDiscoveryURI(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	authConfig := &fakeAuthConfig{
		DiscoveryURLPrefix: "/auth",
	}
	authConfig.EnableTLS = false

	cfg.DiscoveryURL = newFakeAuthServer(authConfig).getLocation()
	cfg.Listen = randomLocalHost
	cfg.ListenHTTP = ""

	proxy, err := proxy.NewProxy(cfg, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, proxy)
	assert.NotNil(t, proxy.Config)
	assert.NotNil(t, proxy.Router)
	assert.NotNil(t, proxy.Endpoint)
	_, err = proxy.Run()
	require.NoError(t, err)
}

func TestReverseProxyHeaders(t *testing.T) {
	proxy := newFakeProxy(nil, &fakeAuthConfig{})
	token := NewTestToken(proxy.idp.getLocation())
	token.addRealmRoles([]string{FakeAdminRole})
	jwt, _ := token.GetToken()
	uri := "/auth_all/test"
	requests := []fakeRequest{
		{
			URI:           uri,
			RawToken:      jwt,
			ExpectedProxy: true,
			ExpectedProxyHeaders: map[string]string{
				"X-Auth-Email":    "gambol99@gmail.com",
				"X-Auth-Roles":    "role:admin,defaultclient:default",
				"X-Auth-Subject":  token.Claims.Sub,
				"X-Auth-Userid":   "rjayawardene",
				"X-Auth-Username": "rjayawardene",
			},
			ExpectedProxyHeadersValidator: map[string]func(*testing.T, *config.Config, string){
				"X-Auth-Token": func(t *testing.T, c *config.Config, value string) {
					t.Helper()
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
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestClearTextWithEnableEncryptedToken",
			ProxySettings: func(c *config.Config) {
				c.EnableRefreshTokens = true
				c.EnableEncryptedToken = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *config.Config, string){
						"X-Auth-Token": func(t *testing.T, c *config.Config, value string) {
							t.Helper()
							_, err := jwt.ParseSigned(value, constant.SignatureAlgs[:])
							require.NoError(t, err, "Problem parsing X-Auth-Token")
							assert.False(t, checkAccessTokenEncryption(t, c, value))
						},
					},
				},
				{
					URI:           FakeAuthAllURL,
					ExpectedProxy: true,
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *config.Config, string){
						"X-Auth-Token": func(t *testing.T, c *config.Config, value string) {
							t.Helper()
							_, err := jwt.ParseSigned(value, constant.SignatureAlgs[:])
							require.NoError(t, err, "Problem parsing X-Auth-Token")
							assert.False(t, checkAccessTokenEncryption(t, c, value))
						},
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestClearTextWithForceEncryptedCookie",
			ProxySettings: func(c *config.Config) {
				c.EnableEncryptedToken = false
				c.ForceEncryptedCookie = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *config.Config, string){
						"X-Auth-Token": func(t *testing.T, c *config.Config, value string) {
							t.Helper()
							_, err := jwt.ParseSigned(value, constant.SignatureAlgs[:])
							require.NoError(t, err, "Problem parsing X-Auth-Token")
							assert.False(t, checkAccessTokenEncryption(t, c, value))
						},
					},
				},
				{
					URI:           FakeAuthAllURL,
					ExpectedProxy: true,
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *config.Config, string){
						"X-Auth-Token": func(t *testing.T, c *config.Config, value string) {
							t.Helper()
							_, err := jwt.ParseSigned(value, constant.SignatureAlgs[:])
							require.NoError(t, err, "Problem parsing X-Auth-Token")
							assert.False(t, checkAccessTokenEncryption(t, c, value))
						},
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
	}

	for _, testCase := range testCases {
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
	// commented out because of https://github.com/golang/go/issues/51416
	// errChan := make(chan error)
	// middleProxy, lstn, err := createTestProxy()
	// middleProxyURL := fmt.Sprintf("http://%s", lstn.Addr().String())
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// go func() {
	// 	errChan <- middleProxy.Serve(lstn)
	// }()

	fakeUpstream := httptest.NewServer(&FakeUpstreamService{})
	upstreamConfig := newFakeKeycloakConfig()
	upstreamConfig.EnableUma = true
	upstreamConfig.NoRedirects = true
	upstreamConfig.EnableDefaultDeny = true
	upstreamConfig.ClientID = ValidUsername
	upstreamConfig.ClientSecret = ValidPassword
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
		&fakeAuthConfig{Expiration: 900 * time.Millisecond},
	)

	testCases := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestPasswordGrant",
			ProxySettings: func(conf *config.Config) {
				conf.EnableForwarding = true
				conf.ForwardingDomains = []string{}
				conf.ForwardingUsername = ValidUsername
				conf.ForwardingPassword = ValidPassword
				conf.ForwardingGrantType = configcore.GrantTypeUserCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
				conf.OpenIDProviderTimeout = 30 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     upstreamProxy.getServiceURL() + FakeTestURL,
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "Bearer ey",
				},
			},
		},
		{
			Name: "TestPasswordGrantWithRefreshing",
			ProxySettings: func(conf *config.Config) {
				conf.EnableForwarding = true
				conf.ForwardingDomains = []string{}
				conf.ForwardingUsername = ValidUsername
				conf.ForwardingPassword = ValidPassword
				conf.ForwardingGrantType = configcore.GrantTypeUserCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     upstreamProxy.getServiceURL() + FakeTestURL,
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					OnResponse:              delay,
					ExpectedContentContains: "Bearer ey",
				},
				{
					URL:                     upstreamProxy.getServiceURL() + FakeTestURL,
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "Bearer ey",
				},
			},
		},
		{
			Name: "TestClientCredentialsGrant",
			ProxySettings: func(conf *config.Config) {
				conf.EnableForwarding = true
				conf.ForwardingDomains = []string{}
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
				conf.ForwardingGrantType = configcore.GrantTypeClientCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     upstreamProxy.getServiceURL() + FakeTestURL,
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "Bearer ey",
					Method:                  "POST",
					FormValues: map[string]string{
						"Name": "Whatever",
					},
					ExpectedContent: func(body string, _ int) {
						assert.Contains(t, body, FakeTestURL)
						assert.Contains(t, body, "method")
						assert.Contains(t, body, "Whatever")
						assert.NotContains(t, body, TestProxyHeaderVal)
					},
				},
			},
		},
		{
			Name: "TestClientCredentialsGrantWithRefreshing",
			ProxySettings: func(conf *config.Config) {
				conf.EnableForwarding = true
				conf.ForwardingDomains = []string{}
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
				conf.ForwardingGrantType = configcore.GrantTypeClientCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     upstreamProxy.getServiceURL() + FakeTestURL,
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					OnResponse:              delay,
					ExpectedContentContains: "Bearer ey",
				},
				{
					URL:                     upstreamProxy.getServiceURL() + FakeTestURL,
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "Bearer ey",
				},
			},
		},
		// commented out because of https://github.com/golang/go/issues/51416
		// {
		// 	// request -> forwardingProxy -> middleProxy -> our backend upstreamProxy
		// 	Name: "TestClientCredentialsGrantWithMiddleProxy",
		// 	ProxySettings: func(conf *config.Config) {
		// 		conf.EnableForwarding = true
		// 		conf.ForwardingDomains = []string{}
		// 		conf.ClientID = ValidUsername
		// 		conf.ClientSecret = ValidPassword
		// 		conf.ForwardingGrantType = configcore.GrantTypeClientCreds
		// 		conf.PatRetryCount = 5
		// 		conf.PatRetryInterval = 2 * time.Second
		// 		conf.UpstreamProxy = middleProxyURL
		// 		conf.Upstream = upstreamProxy.getServiceURL()
		// 	},
		// 	ExecutionSettings: []fakeRequest{
		// 		{
		// 			URL:                     upstreamProxy.getServiceURL() + FakeTestURL,
		// 			ProxyRequest:            true,
		// 			ExpectedProxy:           true,
		// 			ExpectedCode:            http.StatusOK,
		// 			ExpectedContentContains: "Bearer ey",
		// 			Method:                  "POST",
		// 			FormValues: map[string]string{
		// 				"Name": "Whatever",
		// 			},
		// 			ExpectedContent: func(body string, testNum int) {
		// 				assert.Contains(t, body, FakeTestURL)
		// 				assert.Contains(t, body, "method")
		// 				assert.Contains(t, body, "Whatever")
		// 				assert.Contains(t, body, TestProxyHeaderVal)
		// 			},
		// 		},
		// 	},
		// },
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				forwardingConfig := newFakeKeycloakConfig()

				testCase.ProxySettings(forwardingConfig)
				forwardingProxy := newFakeProxy(
					forwardingConfig,
					&fakeAuthConfig{},
				)

				<-time.After(time.Duration(100) * time.Millisecond)
				forwardingProxy.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}

	// select {
	// case err = <-errChan:
	// 	if err != nil && !errors.Is(err, http.ErrServerClosed) {
	// 		t.Fatal(errors.Join(ErrRunHTTPServer, err))
	// 	}
	// default:
	// 	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	// 	defer cancel()
	// 	err = middleProxy.Shutdown(ctx)
	// 	if err != nil {
	// 		t.Fatal(errors.Join(ErrShutHTTPServer, err))
	// 	}
	// }
}

func TestUmaForwardingProxy(t *testing.T) {
	fakeUpstream := httptest.NewServer(&FakeUpstreamService{})
	upstreamConfig := newFakeKeycloakConfig()
	upstreamConfig.EnableUma = true
	upstreamConfig.NoRedirects = true
	upstreamConfig.EnableDefaultDeny = true
	upstreamConfig.ClientID = ValidUsername
	upstreamConfig.ClientSecret = ValidPassword
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
		ProxySettings     func(conf *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestPasswordGrant",
			ProxySettings: func(conf *config.Config) {
				conf.EnableForwarding = true
				conf.EnableUma = true
				conf.ForwardingDomains = []string{}
				conf.ForwardingUsername = ValidUsername
				conf.ForwardingPassword = ValidPassword
				conf.ForwardingGrantType = configcore.GrantTypeUserCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
				conf.OpenIDProviderTimeout = 30 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     upstreamProxy.getServiceURL() + FakeTestURL,
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "gambol",
				},
			},
		},
		{
			Name: "TestPasswordGrantWithRefreshing",
			ProxySettings: func(conf *config.Config) {
				conf.EnableForwarding = true
				conf.EnableUma = true
				conf.ForwardingDomains = []string{}
				conf.ForwardingUsername = ValidUsername
				conf.ForwardingPassword = ValidPassword
				conf.ForwardingGrantType = configcore.GrantTypeUserCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     upstreamProxy.getServiceURL() + FakeTestURL,
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					OnResponse:              delay,
					ExpectedContentContains: "gambol",
				},
				{
					URL:                     upstreamProxy.getServiceURL() + FakeTestURL,
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "gambol",
				},
			},
		},
		{
			Name: "TestClientCredentialsGrant",
			ProxySettings: func(conf *config.Config) {
				conf.EnableForwarding = true
				conf.EnableUma = true
				conf.ForwardingDomains = []string{}
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
				conf.ForwardingGrantType = configcore.GrantTypeClientCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     upstreamProxy.getServiceURL() + FakeTestURL,
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "gambol",
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				forwardingConfig := newFakeKeycloakConfig()

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
	cfg.ForwardingUsername = ValidUsername
	cfg.ForwardingPassword = ValidPassword
	cfg.SkipOpenIDProviderTLSVerify = true
	cfg.ForwardingGrantType = constant.ForwardingGrantTypePassword
	s := httptest.NewServer(&FakeUpstreamService{})
	requests := []fakeRequest{
		{
			URL:                     s.URL + FakeTestURL,
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
				t.Fatal(apperrors.ErrAssertionFailed.Error())
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

func TestEnableHmacForwardingProxy(t *testing.T) {
	fakeUpstream := httptest.NewServer(&FakeUpstreamService{})
	encKey := "sdkljfalisujeoir"
	upstreamConfig := newFakeKeycloakConfig()
	upstreamConfig.EnableHmac = true
	upstreamConfig.EncryptionKey = encKey
	upstreamConfig.NoRedirects = true
	upstreamConfig.EnableDefaultDeny = true
	upstreamConfig.ClientID = ValidUsername
	upstreamConfig.ClientSecret = ValidPassword
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
		ProxySettings     func(conf *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestWithEnableHmacOnBothSides",
			ProxySettings: func(conf *config.Config) {
				conf.EnableForwarding = true
				conf.EnableHmac = true
				conf.EncryptionKey = encKey
				conf.ForwardingDomains = []string{}
				conf.ForwardingUsername = ValidUsername
				conf.ForwardingPassword = ValidPassword
				conf.ForwardingGrantType = configcore.GrantTypeUserCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
				conf.OpenIDProviderTimeout = 30 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     upstreamProxy.getServiceURL() + FakeTestURL,
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "gambol",
				},
			},
		},
		{
			Name: "TestWithDisabledHmacOnForward",
			ProxySettings: func(conf *config.Config) {
				conf.EnableForwarding = true
				conf.EnableHmac = false
				conf.EncryptionKey = encKey
				conf.ForwardingDomains = []string{}
				conf.ForwardingUsername = ValidUsername
				conf.ForwardingPassword = ValidPassword
				conf.ForwardingGrantType = configcore.GrantTypeUserCreds
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
				conf.OpenIDProviderTimeout = 30 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:           upstreamProxy.getServiceURL() + FakeTestURL,
					ProxyRequest:  true,
					ExpectedProxy: false,
					ExpectedCode:  http.StatusBadRequest,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
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

				forwardingProxy.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestForbiddenTemplate(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.ForbiddenPage = "../../templates/forbidden.html.tmpl"
	cfg.Resources = []*authorization.Resource{
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{FakeAdminRole},
		},
	}
	requests := []fakeRequest{
		{
			URI:                     FakeTestURL,
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
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestErrorTemplateDisplayed",
			ProxySettings: func(c *config.Config) {
				c.ErrorPage = "../../templates/error.html.tmpl"
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
			ProxySettings: func(c *config.Config) {
				c.ErrorPage = "../../templates/error-bad-formatted.html.tmpl"
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
			ProxySettings: func(c *config.Config) {
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
	testCases := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
		CatchPanic        bool
	}{
		{
			Name: "TestOkWithSkipTrue",
			ProxySettings: func(c *config.Config) {
				c.SkipOpenIDProviderTLSVerify = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/auth_all/test",
					HasLogin:      true,
					ExpectedProxy: true,
					Redirects:     true,
					ExpectedCode:  http.StatusOK,
				},
			},
			CatchPanic: false,
		},
		{
			Name: "TestOkWithSkipTrueAndIdpSessionCheckTrue",
			ProxySettings: func(c *config.Config) {
				c.SkipOpenIDProviderTLSVerify = true
				c.EnableIDPSessionCheck = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/auth_all/test",
					HasLogin:      true,
					ExpectedProxy: true,
					Redirects:     true,
					ExpectedCode:  http.StatusOK,
				},
			},
			CatchPanic: false,
		},
		{
			Name: "TestPanicWithSkipFalse",
			ProxySettings: func(c *config.Config) {
				c.SkipOpenIDProviderTLSVerify = false
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/auth_all/test",
					HasLogin:      true,
					ExpectedProxy: true,
					Redirects:     true,
					ExpectedCode:  http.StatusOK,
				},
			},
			CatchPanic: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				if testCase.CatchPanic {
					defer func() {
						if r := recover(); r != nil {
							failure, assertOk := r.(string)

							if !assertOk {
								t.Fatal(apperrors.ErrAssertionFailed.Error())
							}

							check := strings.Contains(
								failure,
								"failed to retrieve the provider configuration from discovery url",
							)
							assert.True(t, check)
						}
					}()
				}
				c := newFakeKeycloakConfig()
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{EnableTLS: true})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
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
				t.Fatal(apperrors.ErrAssertionFailed.Error())
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
	token := NewTestToken(proxy.idp.getLocation())
	jwt, _ := token.GetToken()

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
	cfg := newFakeKeycloakConfig()

	testCases := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestDefaultDenialEnabled",
			ProxySettings: func(conf *config.Config) {
				conf.EnableDefaultDeny = true
				conf.Resources = []*authorization.Resource{
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
				{
					URI:       "/not_permited",
					Redirects: false,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
				// lowercase methods should not be valid
				{
					Method:       "get",
					URI:          "/not_permited",
					Redirects:    false,
					ExpectedCode: http.StatusNotImplemented,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
				{
					Method:       "get",
					URI:          "/not_permited",
					Redirects:    true,
					ExpectedCode: http.StatusNotImplemented,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
				// any "crap" methods should not be valid
				{
					Method:       "whAS9023",
					URI:          "/not_permited",
					Redirects:    false,
					ExpectedCode: http.StatusNotImplemented,
					ExpectedContent: func(body string, _ int) {
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
					ExpectedContent: func(body string, _ int) {
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
					ExpectedContent: func(body string, _ int) {
						assert.Contains(t, body, "gzip")
					},
				},
			},
		},
		{
			Name: "TestDefaultDenialDisabled",
			ProxySettings: func(conf *config.Config) {
				conf.EnableDefaultDeny = false
				conf.NoRedirects = true
				conf.Resources = []*authorization.Resource{
					{
						URL:     "/",
						Methods: []string{"GET"},
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                     "/public/allowed",
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					Redirects:               false,
					ExpectedContentContains: "gzip",
				},
				{
					Method:        "GET",
					URI:           "/",
					HasToken:      false,
					ProxyRequest:  false,
					ExpectedProxy: false,
					Redirects:     false,
					ExpectedCode:  http.StatusUnauthorized,
					ExpectedContent: func(body string, _ int) {
						assert.Contains(t, body, "")
					},
				},
				{
					Method:        "GET",
					URI:           "/",
					HasToken:      true,
					ProxyRequest:  true,
					ExpectedProxy: true,
					Redirects:     false,
					ExpectedCode:  http.StatusOK,
					ExpectedContent: func(body string, _ int) {
						assert.Contains(t, body, "gzip")
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		c := *cfg
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(&c)
				p := newFakeProxy(&c, &fakeAuthConfig{})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
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
		{
			URL:     "/",
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
			ExpectedContent: func(body string, _ int) {
				assert.Equal(t, "", body)
			},
		},
		// lowercase methods should not be valid
		{
			Method:       "get",
			URI:          "/not_permited",
			Redirects:    false,
			ExpectedCode: http.StatusNotImplemented,
			ExpectedContent: func(body string, _ int) {
				assert.Equal(t, "", body)
			},
		},
		// any "crap" methods should not be valid
		{
			Method:       "whAS9023",
			URI:          "/not_permited",
			Redirects:    false,
			ExpectedCode: http.StatusNotImplemented,
			ExpectedContent: func(body string, _ int) {
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
			ExpectedCode:  http.StatusForbidden,
			ExpectedContent: func(body string, _ int) {
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
			ExpectedCode:  http.StatusForbidden,
			ExpectedContent: func(body string, _ int) {
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
			ExpectedContent: func(body string, _ int) {
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
			ExpectedCode:  http.StatusForbidden,
			ExpectedContent: func(body string, _ int) {
				assert.Equal(t, "", body)
			},
		},
		{
			Method:        "GET",
			URI:           "/",
			HasToken:      true,
			ProxyRequest:  true,
			ExpectedProxy: true,
			Redirects:     false,
			ExpectedCode:  http.StatusOK,
			ExpectedContent: func(body string, _ int) {
				assert.Contains(t, body, "gzip")
			},
		},
		{
			Method:        http.MethodPost,
			URI:           "/",
			HasToken:      true,
			ProxyRequest:  true,
			ExpectedProxy: false,
			Redirects:     false,
			ExpectedCode:  http.StatusForbidden,
			ExpectedContent: func(body string, _ int) {
				assert.Equal(t, "", body)
			},
		},
	}
	newFakeProxy(config, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestNoProxy(t *testing.T) {
	testCases := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestNoProxyWithNoRedirectsWhiteListed",
			ProxySettings: func(c *config.Config) {
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
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
		{
			Name: "TestNoProxyWithNoRedirectsPrivateUnauthenticated",
			ProxySettings: func(c *config.Config) {
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
					URI:           "/private",
					ExpectedProxy: false,
					ExpectedCode:  http.StatusUnauthorized,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
		{
			Name: "TestNoProxyWithRedirectsPrivateUnauthenticated",
			ProxySettings: func(c *config.Config) {
				c.EnableDefaultDeny = true
				c.NoRedirects = false
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
					URI:           "/private",
					ExpectedProxy: false,
					Redirects:     true,
					ExpectedCode:  http.StatusSeeOther,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
					ExpectedLocation: "https://thiswillbereplaced/oauth",
					Headers: map[string]string{
						constant.HeaderXForwardedHost:  "thiswillbereplaced",
						constant.HeaderXForwardedProto: "https",
					},
				},
			},
		},
		{
			Name: "TestNoProxyWithRedirectsPrivateUnauthenticatedMissingXFORWARDED",
			ProxySettings: func(c *config.Config) {
				c.EnableDefaultDeny = true
				c.NoRedirects = false
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
					URI:           "/private",
					ExpectedProxy: false,
					Redirects:     true,
					ExpectedCode:  http.StatusForbidden,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
		{
			Name: "TestNoProxyWithRedirectsPrivateAuthenticated",
			ProxySettings: func(c *config.Config) {
				c.EnableDefaultDeny = false
				c.NoRedirects = false
				c.NoProxy = true
				c.Resources = []*authorization.Resource{
					{
						URL:     "/*",
						Methods: utils.AllHTTPMethods,
						Roles:   []string{"user"},
					},
					{
						URL:         "/public/*",
						Methods:     utils.AllHTTPMethods,
						WhiteListed: true,
					},
					{
						URL:     "/private",
						Methods: []string{"POST"},
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					// forward-auth will send / as path always so we are simulating it
					// real path will be sent in X-Forwarded-Uri, which should be
					// injected to request path in forward-auth middleware
					URI:             "/",
					ExpectedProxy:   false,
					HasLogin:        true,
					LoginXforwarded: true,
					Redirects:       true,
					ExpectedCode:    http.StatusOK,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
					Headers: map[string]string{
						constant.HeaderXForwardedURI:    "/private",
						constant.HeaderXForwardedMethod: "POST",
					},
				},
				{
					URI:             "/",
					ExpectedProxy:   false,
					HasLogin:        true,
					LoginXforwarded: true,
					Redirects:       true,
					ExpectedCode:    http.StatusForbidden,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
					Headers: map[string]string{
						constant.HeaderXForwardedURI:    "/private",
						constant.HeaderXForwardedMethod: "DELETE",
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
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
	cfg.SignInPage = "../../templates/sign_in.html.tmpl"
	uri := utils.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.AuthorizationURL)
	cfg.Resources = []*authorization.Resource{
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{FakeAdminRole},
		},
	}
	requests := []fakeRequest{
		{
			URI:                     uri,
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
			URI:           FakeAuthAllURL + FakeTestURL,
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedProxyHeaders: map[string]string{
				constant.HeaderXForwardedFor: "127.0.0.1",
			},
			ExpectedCode: http.StatusOK,
		},
		{
			URI:           FakeAuthAllURL + FakeTestURL,
			HasToken:      true,
			ProxyProtocol: "189.10.10.1",
			ExpectedProxy: true,
			ExpectedProxyHeaders: map[string]string{
				constant.HeaderXForwardedFor: "189.10.10.1",
			},
			ExpectedCode: http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestXForwarded(t *testing.T) {
	testCases := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestEmptyXForwardedFor",
			ProxySettings: func(_ *config.Config) {
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL + FakeTestURL,
					HasToken:      true,
					ExpectedProxy: true,
					ExpectedProxyHeaders: map[string]string{
						constant.HeaderXForwardedFor: "127.0.0.1",
						constant.HeaderXRealIP:       "127.0.0.1",
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestXForwardedForPresent",
			ProxySettings: func(_ *config.Config) {
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL + FakeTestURL,
					HasToken:      true,
					ExpectedProxy: true,
					Headers: map[string]string{
						constant.HeaderXForwardedFor: "189.10.10.1",
					},
					ExpectedProxyHeaders: map[string]string{
						constant.HeaderXForwardedFor: "189.10.10.1",
						constant.HeaderXRealIP:       "189.10.10.1",
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestXRealIP",
			ProxySettings: func(_ *config.Config) {
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL + FakeTestURL,
					HasToken:      true,
					ExpectedProxy: true,
					Headers: map[string]string{
						constant.HeaderXRealIP: "189.10.10.1",
					},
					ExpectedProxyHeaders: map[string]string{
						constant.HeaderXForwardedFor: "189.10.10.1",
						constant.HeaderXRealIP:       "189.10.10.1",
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestEmptyXForwardedHost",
			ProxySettings: func(_ *config.Config) {
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL + FakeTestURL,
					HasToken:      true,
					ExpectedProxy: true,
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *config.Config, string){
						constant.HeaderXForwardedHost: func(t *testing.T, _ *config.Config, value string) {
							t.Helper()
							assert.Contains(t, value, "127.0.0.1")
						},
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestXForwardedHostPresent",
			ProxySettings: func(_ *config.Config) {
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL + FakeTestURL,
					HasToken:      true,
					ExpectedProxy: true,
					Headers: map[string]string{
						constant.HeaderXForwardedHost: "189.10.10.1",
					},
					ExpectedProxyHeaders: map[string]string{
						constant.HeaderXForwardedHost: "189.10.10.1",
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestEmptyXForwardedHost",
			ProxySettings: func(_ *config.Config) {
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL + FakeTestURL,
					HasToken:      true,
					ExpectedProxy: true,
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *config.Config, string){
						"X-Forwarded-Host": func(t *testing.T, _ *config.Config, value string) {
							t.Helper()
							assert.Contains(t, value, "127.0.0.1")
						},
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestXForwardedHostPresent",
			ProxySettings: func(_ *config.Config) {
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL + FakeTestURL,
					HasToken:      true,
					ExpectedProxy: true,
					Headers: map[string]string{
						"X-Forwarded-Host": "189.10.10.1",
					},
					ExpectedProxyHeaders: map[string]string{
						"X-Forwarded-Host": "189.10.10.1",
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
	}

	for _, testCase := range testCases {
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

	testCases := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestNoRedirects",
			ProxySettings: func(conf *config.Config) {
				conf.NoRedirects = true
			},
			ExecutionSettings: []fakeRequest{
				// the token must be encrypted
				{
					URI:          "/auth_all/test",
					HasToken:     true,
					ExpectedCode: http.StatusUnauthorized,
				},
			},
		},
		{
			Name: "TestRedirects",
			ProxySettings: func(conf *config.Config) {
				conf.NoRedirects = false
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/auth_all/test",
					HasLogin:      true,
					ExpectedProxy: true,
					Redirects:     true,
					ExpectedProxyHeaders: map[string]string{
						"X-Auth-Email":               "gambol99@gmail.com",
						"X-Auth-Userid":              "rjayawardene",
						"X-Auth-Username":            "rjayawardene",
						constant.HeaderXForwardedFor: "127.0.0.1",
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
	}

	for _, testCase := range testCases {
		cfg := *cfg
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(&cfg)
				newFakeProxy(&cfg, &fakeAuthConfig{}).RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
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
	cfg := newFakeKeycloakConfig()
	proxySkipCheckFalse := newFakeProxy(cfg, &fakeAuthConfig{})

	// create two token, one with a bad client id
	bad := NewTestToken(proxySkipCheckFalse.idp.getLocation())
	iss := "bad_client_id"
	bad.Claims.Aud = iss
	badSigned, _ := bad.GetToken()
	// and the good
	good := NewTestToken(proxySkipCheckFalse.idp.getLocation())
	goodSigned, _ := good.GetToken()

	requestsSkipCheckFalse := []fakeRequest{
		{
			URI:               "/auth_all/test",
			RawToken:          goodSigned,
			ExpectedProxy:     true,
			ExpectedCode:      http.StatusOK,
			SkipClientIDCheck: false,
		},
		{
			URI:               "/auth_all/test",
			RawToken:          badSigned,
			ExpectedCode:      http.StatusForbidden,
			ExpectedProxy:     false,
			SkipClientIDCheck: false,
		},
	}

	proxySkipCheckFalse.RunTests(t, requestsSkipCheckFalse)

	cfg = newFakeKeycloakConfig()
	cfg.SkipAccessTokenClientIDCheck = true
	proxySkipCheckTrue := newFakeProxy(cfg, &fakeAuthConfig{})
	// create two token, one with a bad client id
	bad = NewTestToken(proxySkipCheckTrue.idp.getLocation())
	bad.Claims.Aud = iss
	badSigned, _ = bad.GetToken()
	// and the good
	good = NewTestToken(proxySkipCheckTrue.idp.getLocation())
	goodSigned, _ = good.GetToken()

	requestsSkipCheckTrue := []fakeRequest{
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
			ExpectedProxy:     true,
			ExpectedCode:      http.StatusOK,
			SkipClientIDCheck: true,
		},
	}
	proxySkipCheckTrue.RunTests(t, requestsSkipCheckTrue)
}

func TestSkipIssuer(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	iss := "bad_issuer"
	proxySkipFalse := newFakeProxy(cfg, &fakeAuthConfig{})
	// create two token, one with a bad client id
	bad := NewTestToken(proxySkipFalse.idp.getLocation())
	bad.Claims.Iss = iss
	badSigned, _ := bad.GetToken()
	// and the good
	good := NewTestToken(proxySkipFalse.idp.getLocation())
	goodSigned, _ := good.GetToken()
	requestsSkipFalse := []fakeRequest{
		{
			URI:             "/auth_all/test",
			RawToken:        goodSigned,
			ExpectedProxy:   true,
			ExpectedCode:    http.StatusOK,
			SkipIssuerCheck: false,
		},
		{
			URI:             "/auth_all/test",
			RawToken:        badSigned,
			ExpectedCode:    http.StatusForbidden,
			ExpectedProxy:   false,
			SkipIssuerCheck: false,
		},
	}
	proxySkipFalse.RunTests(t, requestsSkipFalse)

	cfg = newFakeKeycloakConfig()
	cfg.SkipAccessTokenIssuerCheck = true
	proxySkipTrue := newFakeProxy(cfg, &fakeAuthConfig{})
	// create two token, one with a bad client id
	bad = NewTestToken(proxySkipTrue.idp.getLocation())
	bad.Claims.Iss = iss
	badSigned, _ = bad.GetToken()
	// and the good
	good = NewTestToken(proxySkipTrue.idp.getLocation())
	goodSigned, _ = good.GetToken()
	requestsSkipTrue := []fakeRequest{
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
			ExpectedProxy:   true,
			ExpectedCode:    http.StatusOK,
			SkipIssuerCheck: true,
		},
	}
	proxySkipTrue.RunTests(t, requestsSkipTrue)
}

func TestAuthTokenHeaderEnabled(t *testing.T) {
	proxy := newFakeProxy(nil, &fakeAuthConfig{})
	token := NewTestToken(proxy.idp.getLocation())
	signed, _ := token.GetToken()

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
	token := NewTestToken(proxy.idp.getLocation())
	signed, _ := token.GetToken()

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
		ProxySettings     func(conf *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestProxyTLS",
			ProxySettings: func(conf *config.Config) {
				conf.EnableDefaultDeny = true
				//nolint:gosec
				conf.TLSCertificate = os.TempDir() + FakeCertFilePrefix + strconv.Itoa(rand.Intn(10000))
				//nolint:gosec
				conf.TLSPrivateKey = os.TempDir() + FakePrivFilePrefix + strconv.Itoa(rand.Intn(10000))
				//nolint:gosec
				conf.TLSCaCertificate = os.TempDir() + FakeCaFilePrefix + strconv.Itoa(rand.Intn(10000))
				conf.Listen = testProxyAddr
				conf.NoRedirects = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:          fmt.Sprintf("https://%s/test", testProxyAddr),
					ExpectedCode: http.StatusUnauthorized,
					RequestCA:    fakeCA,
					Redirects:    false,
				},
			},
		},
		{
			Name: "TestProxyTLSMatch",
			ProxySettings: func(conf *config.Config) {
				conf.EnableDefaultDeny = true
				//nolint:gosec
				conf.TLSCertificate = os.TempDir() + FakeCertFilePrefix + strconv.Itoa(rand.Intn(10000))
				//nolint:gosec
				conf.TLSPrivateKey = os.TempDir() + FakePrivFilePrefix + strconv.Itoa(rand.Intn(10000))
				//nolint:gosec
				conf.TLSCaCertificate = os.TempDir() + FakeCaFilePrefix + strconv.Itoa(rand.Intn(10000))
				conf.Listen = testProxyAddr
				conf.TLSMinVersion = constant.TLS13
				conf.NoRedirects = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:          fmt.Sprintf("https://%s/test", testProxyAddr),
					ExpectedCode: http.StatusUnauthorized,
					RequestCA:    fakeCA,
					TLSMin:       tls.VersionTLS13,
					Redirects:    false,
				},
			},
		},
		{
			Name: "TestProxyTLSDiffer",
			ProxySettings: func(conf *config.Config) {
				conf.EnableDefaultDeny = true
				//nolint:gosec
				conf.TLSCertificate = os.TempDir() + FakeCertFilePrefix + strconv.Itoa(rand.Intn(10000))
				//nolint:gosec
				conf.TLSPrivateKey = os.TempDir() + FakePrivFilePrefix + strconv.Itoa(rand.Intn(10000))
				//nolint:gosec
				conf.TLSCaCertificate = os.TempDir() + FakeCaFilePrefix + strconv.Itoa(rand.Intn(10000))
				conf.Listen = testProxyAddr
				conf.TLSMinVersion = constant.TLS12
				conf.NoRedirects = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:          fmt.Sprintf("https://%s/test", testProxyAddr),
					ExpectedCode: http.StatusUnauthorized,
					RequestCA:    fakeCA,
					TLSMin:       tls.VersionTLS13,
					Redirects:    false,
				},
			},
		},
		{
			Name: "TestProxyTLSMinNotFullfilled",
			ProxySettings: func(conf *config.Config) {
				conf.EnableDefaultDeny = true
				//nolint:gosec
				conf.TLSCertificate = os.TempDir() + FakeCertFilePrefix + strconv.Itoa(rand.Intn(10000))
				//nolint:gosec
				conf.TLSPrivateKey = os.TempDir() + FakePrivFilePrefix + strconv.Itoa(rand.Intn(10000))
				//nolint:gosec
				conf.TLSCaCertificate = os.TempDir() + FakeCaFilePrefix + strconv.Itoa(rand.Intn(10000))
				conf.Listen = testProxyAddr
				conf.TLSMinVersion = constant.TLS13
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
					err := os.WriteFile(certFile, fakeCertByte, 0600)

					if err != nil {
						t.Fatalf("Problem writing certificate %s", err)
					}
					defer os.Remove(certFile)
				}

				if privFile != "" {
					fakeKeyByte := []byte(fakePrivateKey)
					err := os.WriteFile(privFile, fakeKeyByte, 0600)

					if err != nil {
						t.Fatalf("Problem writing privateKey %s", err)
					}
					defer os.Remove(privFile)
				}

				if caFile != "" {
					fakeCAByte := []byte(fakeCA)
					err := os.WriteFile(caFile, fakeCAByte, 0600)

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
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestPublicAllow",
			ProxySettings: func(c *config.Config) {
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
			ProxySettings: func(c *config.Config) {
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
			ProxySettings: func(c *config.Config) {
				c.EnableDefaultDeny = true
				c.CustomHTTPMethods = []string{"PROPFIND"} // WebDav method
				c.NoRedirects = true
			},
			ExecutionSettings: []fakeRequest{
				{
					Method:        "PROPFIND",
					URI:           "/api/test",
					ExpectedProxy: false,
					Redirects:     false,
					ExpectedCode:  http.StatusUnauthorized,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
		{
			Name: "TestDefaultDenialPassOnCustomHTTP",
			ProxySettings: func(c *config.Config) {
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
			ProxySettings: func(c *config.Config) {
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
			ProxySettings: func(c *config.Config) {
				c.EnableDefaultDeny = true
				c.CustomHTTPMethods = []string{"PROPFIND"} // WebDav method
				c.NoRedirects = true
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
					Redirects:     false,
					ExpectedCode:  http.StatusUnauthorized,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
		{
			Name: "TestProtectionOnCustomHTTPWithUnvalidRequestMethod",
			ProxySettings: func(c *config.Config) {
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
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
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

func TestGraceTimeout(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableForwarding = true
	cfg.PatRetryCount = 5
	cfg.PatRetryInterval = 2 * time.Second
	cfg.OpenIDProviderTimeout = 30 * time.Second
	cfg.ForwardingDomains = []string{}
	cfg.ForwardingUsername = ValidUsername
	cfg.ForwardingPassword = ValidPassword
	cfg.SkipOpenIDProviderTLSVerify = true
	cfg.ForwardingGrantType = constant.ForwardingGrantTypePassword

	fakeServer := httptest.NewServer(&FakeUpstreamService{})

	testCases := []struct {
		Name                 string
		ServerGraceTimeout   time.Duration
		ResponseDelay        string
		ExpectedCode         int
		ExpectedRequestError string
		ExpectedProxy        bool
	}{
		{
			Name:                 "TestGraceTimeout",
			ServerGraceTimeout:   2 * time.Second,
			ResponseDelay:        "1",
			ExpectedCode:         http.StatusOK,
			ExpectedRequestError: "",
			ExpectedProxy:        true,
		},
		// {
		// 	Name:                 "TestGraceTimeoutClosedServer",
		// 	ServerGraceTimeout:   time.Second,
		// 	ResponseDelay:        "2",
		// 	ExpectedCode:         0,
		// 	ExpectedRequestError: "EOF",
		// 	ExpectedProxy:        false,
		// },
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				cfg.ServerGraceTimeout = testCase.ServerGraceTimeout

				var waitShutdown sync.WaitGroup
				waitShutdown.Add(1)

				requests := []fakeRequest{
					{
						URL:                  fakeServer.URL + FakeTestURL,
						ProxyRequest:         true,
						ExpectedProxy:        testCase.ExpectedProxy,
						ExpectedCode:         testCase.ExpectedCode,
						ExpectedRequestError: testCase.ExpectedRequestError,
						Headers:              map[string]string{"delay": testCase.ResponseDelay},
					},
				}

				proxy := newFakeProxy(cfg, &fakeAuthConfig{EnableTLS: true})
				<-time.After(time.Duration(100) * time.Millisecond)

				go func() {
					defer waitShutdown.Done()
					<-time.After(time.Duration(200) * time.Millisecond)
					if err := proxy.Shutdown(); err != nil {
						t.Error("Failed to shutdown proxy")
					}
				}()
				proxy.RunTests(t, requests)
				waitShutdown.Wait()
			},
		)
	}
}

// commented out because of see https://github.com/golang/go/issues/51416
// func TestUpstreamProxy(t *testing.T) {
// 	errChan := make(chan error)
// 	upstream := httptest.NewServer(&FakeUpstreamService{})
// 	upstreamProxy, lstn, err := createTestProxy()
// 	upstreamProxyURL := fmt.Sprintf("http://%s", lstn.Addr().String())
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	go func() {
// 		errChan <- upstreamProxy.Serve(lstn)
// 	}()

// 	testCases := []struct {
// 		Name              string
// 		ProxySettings     func(c *config.Config)
// 		ExecutionSettings []fakeRequest
// 	}{
// 		{
// 			Name: "TestUpstreamProxy",
// 			ProxySettings: func(c *config.Config) {
// 				c.UpstreamProxy = upstreamProxyURL
// 				c.Upstream = upstream.URL
// 			},
// 			ExecutionSettings: []fakeRequest{
// 				{
// 					URI:    "/test",
// 					Method: "POST",
// 					FormValues: map[string]string{
// 						"Name": "Whatever",
// 					},
// 					ExpectedProxy:           true,
// 					ExpectedCode:            http.StatusOK,
// 					ExpectedContentContains: "gzip",
// 					ExpectedContent: func(body string, testNum int) {
// 						assert.Contains(t, body, FakeTestURL)
// 						assert.Contains(t, body, "method")
// 						assert.Contains(t, body, "Whatever")
// 						assert.Contains(t, body, TestProxyHeaderVal)
// 					},
// 				},
// 			},
// 		},
// 		{
// 			Name: "TestNoUpstreamProxy",
// 			ProxySettings: func(c *config.Config) {
// 				c.Upstream = upstream.URL
// 			},
// 			ExecutionSettings: []fakeRequest{
// 				{
// 					URI:    FakeTestURL,
// 					Method: "POST",
// 					FormValues: map[string]string{
// 						"Name": "Whatever",
// 					},
// 					ExpectedProxy:           true,
// 					ExpectedCode:            http.StatusOK,
// 					ExpectedContentContains: "gzip",
// 					ExpectedContent: func(body string, testNum int) {
// 						assert.Contains(t, body, FakeTestURL)
// 						assert.Contains(t, body, "method")
// 						assert.Contains(t, body, "Whatever")
// 						assert.NotContains(t, body, TestProxyHeaderVal)
// 					},
// 				},
// 			},
// 		},
// 	}

// 	for _, testCase := range testCases {
// 		testCase := testCase
// 		t.Run(
// 			testCase.Name,
// 			func(t *testing.T) {
// 				c := newFakeKeycloakConfig()
// 				testCase.ProxySettings(c)
// 				p := newFakeProxy(c, &fakeAuthConfig{})
// 				p.RunTests(t, testCase.ExecutionSettings)
// 			},
// 		)
// 	}

// 	select {
// 	case err = <-errChan:
// 		if err != nil && !errors.Is(err, http.ErrServerClosed) {
// 			t.Fatal(errors.Join(ErrRunHTTPServer, err))
// 		}
// 	default:
// 		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
// 		defer cancel()
// 		err = upstreamProxy.Shutdown(ctx)
// 		if err != nil {
// 			t.Fatal(errors.Join(ErrShutHTTPServer, err))
// 		}
// 	}
// }
