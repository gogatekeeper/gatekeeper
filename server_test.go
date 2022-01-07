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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	p := newFakeProxy(nil, &fakeAuthConfig{})
	token := newTestToken(p.idp.getLocation())
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
	p.RunTests(t, requests)
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
	s := httptest.NewServer(&fakeUpstreamService{})

	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestPasswordGrant",
			ProxySettings: func(c *Config) {
				c.EnableForwarding = true
				c.ForwardingDomains = []string{}
				c.ForwardingUsername = validUsername
				c.ForwardingPassword = validPassword
				c.ForwardingGrantType = GrantTypeUserCreds
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     s.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "Bearer ey",
				},
			},
		},
		{
			Name: "TestPasswordGrantWithRefreshing",
			ProxySettings: func(c *Config) {
				c.EnableForwarding = true
				c.ForwardingDomains = []string{}
				c.ForwardingUsername = validUsername
				c.ForwardingPassword = validPassword
				c.ForwardingGrantType = GrantTypeUserCreds
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     s.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					OnResponse:              delay,
					ExpectedContentContains: "Bearer ey",
				},
				{
					URL:                     s.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "Bearer ey",
				},
			},
		},
		{
			Name: "TestClientCredentialsGrant",
			ProxySettings: func(c *Config) {
				c.EnableForwarding = true
				c.ForwardingDomains = []string{}
				c.ClientID = validUsername
				c.ClientSecret = validPassword
				c.ForwardingGrantType = GrantTypeClientCreds
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     s.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "Bearer ey",
				},
			},
		},
		{
			Name: "TestClientCredentialsGrantWithRefreshing",
			ProxySettings: func(c *Config) {
				c.EnableForwarding = true
				c.ForwardingDomains = []string{}
				c.ClientID = validUsername
				c.ClientSecret = validPassword
				c.ForwardingGrantType = GrantTypeClientCreds
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     s.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					OnResponse:              delay,
					ExpectedContentContains: "Bearer ey",
				},
				{
					URL:                     s.URL + "/test",
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
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{Expiration: 900 * time.Millisecond})
				<-time.After(time.Duration(100) * time.Millisecond)
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestSkipOpenIDProviderTLSVerifyForwardingProxy(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableForwarding = true
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
	p := newFakeProxy(cfg, &fakeAuthConfig{EnableTLS: true})
	<-time.After(time.Duration(100) * time.Millisecond)
	p.RunTests(t, requests)

	cfg.SkipOpenIDProviderTLSVerify = false

	defer func() {
		if r := recover(); r != nil {
			check := strings.Contains(
				r.(string),
				"failed to retrieve the provider configuration from discovery url",
			)
			assert.True(t, check)
		}
	}()

	p = newFakeProxy(cfg, &fakeAuthConfig{EnableTLS: true})
	<-time.After(time.Duration(100) * time.Millisecond)
	p.RunTests(t, requests)
}

func TestForbiddenTemplate(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.ForbiddenPage = "templates/forbidden.html.tmpl"
	cfg.Resources = []*Resource{
		{
			URL:     "/*",
			Methods: allHTTPMethods,
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
	c := newFakeKeycloakConfig()
	c.SkipOpenIDProviderTLSVerify = true
	requests := []fakeRequest{
		{
			URI:           "/auth_all/test",
			HasLogin:      true,
			ExpectedProxy: true,
			Redirects:     true,
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(c, &fakeAuthConfig{EnableTLS: true}).RunTests(t, requests)
	c.SkipOpenIDProviderTLSVerify = false

	defer func() {
		if r := recover(); r != nil {
			check := strings.Contains(
				r.(string),
				"failed to retrieve the provider configuration from discovery url",
			)
			assert.True(t, check)
		}
	}()

	newFakeProxy(c, &fakeAuthConfig{EnableTLS: true}).RunTests(t, requests)
}

func TestOpenIDProviderProxy(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.SkipOpenIDProviderTLSVerify = true
	c.OpenIDProviderProxy = "http://127.0.0.1:1000"

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

	newFakeProxy(c, fakeAuthConf).RunTests(t, requests)

	fakeAuthConf = &fakeAuthConfig{
		EnableTLS:   false,
		EnableProxy: false,
	}

	defer func() {
		if r := recover(); r != nil {
			check := strings.Contains(
				r.(string),
				"failed to retrieve the provider configuration from discovery url",
			)
			assert.True(t, check)
		}
	}()

	newFakeProxy(c, fakeAuthConf).RunTests(t, requests)
}

func TestRequestIDHeader(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableRequestID = true
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
	newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestAuthTokenHeaderDisabled(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableTokenHeader = false
	p := newFakeProxy(c, &fakeAuthConfig{})
	token := newTestToken(p.idp.getLocation())
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
	p.RunTests(t, requests)
}

func TestAudienceHeader(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.NoRedirects = false
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
	newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestDefaultDenial(t *testing.T) {
	config := newFakeKeycloakConfig()
	config.EnableDefaultDeny = true
	config.Resources = []*Resource{
		{
			URL:         "/public/*",
			Methods:     allHTTPMethods,
			WhiteListed: true,
		},
	}
	requests := []fakeRequest{
		{
			URI:           "/public/allowed",
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/not_permited",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			Method:       "get",
			URI:          "/not_permited",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(config, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestAuthorizationTemplate(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.SignInPage = "templates/sign_in.html.tmpl"
	cfg.Resources = []*Resource{
		{
			URL:     "/*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
	}
	requests := []fakeRequest{
		{
			URI:                     cfg.WithOAuthURI(authorizationURL),
			Redirects:               true,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "Sign In",
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestProxyProtocol(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableProxyProtocol = true
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
	newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, requests)
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
	c := newFakeKeycloakConfig()
	c.EnableEncryptedToken = true
	c.EncryptionKey = "US36S5kubc4BXbfzCIKTQcTzG6lvixVv"
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
	newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestCustomResponseHeaders(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.ResponseHeaders = map[string]string{
		"CustomReponseHeader": "True",
	}
	p := newFakeProxy(c, &fakeAuthConfig{})

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
	p.RunTests(t, requests)
}

func TestSkipClientIDDisabled(t *testing.T) {
	// !!!! Before in keycloak in audience of access_token was client_id of
	// client for which was access token released, but this is not according spec
	// as access_token could be also other type not just JWT
	c := newFakeKeycloakConfig()
	p := newFakeProxy(c, &fakeAuthConfig{})
	// create two token, one with a bad client id
	bad := newTestToken(p.idp.getLocation())
	bad.claims.Aud = "bad_client_id"
	badSigned, _ := bad.getToken()
	// and the good
	good := newTestToken(p.idp.getLocation())
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
	p.RunTests(t, requests)
}

func TestSkipIssuer(t *testing.T) {
	c := newFakeKeycloakConfig()
	p := newFakeProxy(c, &fakeAuthConfig{})
	// create two token, one with a bad client id
	bad := newTestToken(p.idp.getLocation())
	bad.claims.Iss = "bad_issuer"
	badSigned, _ := bad.getToken()
	// and the good
	good := newTestToken(p.idp.getLocation())
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
	p.RunTests(t, requests)
}

func TestAuthTokenHeaderEnabled(t *testing.T) {
	p := newFakeProxy(nil, &fakeAuthConfig{})
	token := newTestToken(p.idp.getLocation())
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
	p.RunTests(t, requests)
}

func TestDisableAuthorizationCookie(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableAuthorizationCookies = false
	p := newFakeProxy(c, &fakeAuthConfig{})
	token := newTestToken(p.idp.getLocation())
	signed, _ := token.getToken()

	requests := []fakeRequest{
		{
			URI: "/auth_all/test",
			Cookies: []*http.Cookie{
				{Name: c.CookieAccessName, Value: signed},
				{Name: "mycookie", Value: "myvalue"},
			},
			HasToken:                true,
			ExpectedContentContains: "kc-access=censored; mycookie=myvalue",
			ExpectedCode:            http.StatusOK,
			ExpectedProxy:           true,
		},
	}
	p.RunTests(t, requests)
}
