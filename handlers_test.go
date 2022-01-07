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
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestDebugHandler(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.Resources = make([]*Resource, 0)
	c.EnableProfiling = true
	requests := []fakeRequest{
		{URI: "/debug/pprof/no_there", ExpectedCode: http.StatusNotFound},
		{URI: "/debug/pprof/heap", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/goroutine", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/block", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/threadcreate", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/cmdline", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/trace", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/symbol", ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/symbol", Method: http.MethodPost, ExpectedCode: http.StatusOK},
		{URI: "/debug/pprof/symbol", Method: http.MethodPost, ExpectedCode: http.StatusOK},
	}
	newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestExpirationHandler(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	uri := cfg.WithOAuthURI(expiredURL)
	requests := []fakeRequest{
		{
			URI:          uri,
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:          uri,
			HasToken:     true,
			Expires:      -48 * time.Hour,
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:          uri,
			HasToken:     true,
			Expires:      14 * time.Hour,
			ExpectedCode: http.StatusOK,
		},
	}
	newFakeProxy(nil, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestOauthRequestNotProxying(t *testing.T) {
	requests := []fakeRequest{
		{URI: "/oauth/test"},
		{URI: "/oauth/..//oauth/test/"},
		{URI: "/oauth/expired", Method: http.MethodPost, ExpectedCode: http.StatusMethodNotAllowed},
		{URI: "/oauth/expiring", Method: http.MethodPost},
		{URI: "/oauth%2F///../test%2F%2Foauth"},
	}
	newFakeProxy(nil, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestLoginHandlerDisabled(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableLoginHandler = false
	requests := []fakeRequest{
		{URI: c.WithOAuthURI(loginURL), Method: http.MethodPost, ExpectedCode: http.StatusNotImplemented},
		{URI: c.WithOAuthURI(loginURL), ExpectedCode: http.StatusMethodNotAllowed},
	}
	newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestLoginHandlerNotDisabled(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableLoginHandler = true
	requests := []fakeRequest{
		{URI: "/oauth/login", Method: http.MethodPost, ExpectedCode: http.StatusBadRequest},
	}
	newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestLoginHandler(t *testing.T) {
	c := newFakeKeycloakConfig()
	uri := c.WithOAuthURI(loginURL)

	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name:          "TestFailLoginWithoutCredentials",
			ProxySettings: func(c *Config) {},
			ExecutionSettings: []fakeRequest{
				{
					URI:          uri,
					Method:       http.MethodPost,
					ExpectedCode: http.StatusBadRequest,
				},
			},
		},
		{
			Name:          "TestFailLoginWithoutPassword",
			ProxySettings: func(c *Config) {},
			ExecutionSettings: []fakeRequest{
				{
					URI:          uri,
					Method:       http.MethodPost,
					FormValues:   map[string]string{"username": "test"},
					ExpectedCode: http.StatusBadRequest,
				},
			},
		},
		{
			Name:          "TestFailLoginWithoutUsername",
			ProxySettings: func(c *Config) {},
			ExecutionSettings: []fakeRequest{
				{
					URI:          uri,
					Method:       http.MethodPost,
					FormValues:   map[string]string{"password": "test"},
					ExpectedCode: http.StatusBadRequest,
				},
			},
		},
		{
			Name:          "TestLoginWithGoodCredentials",
			ProxySettings: func(c *Config) {},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "test",
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestLoginWithSkipTokenVerification",
			ProxySettings: func(c *Config) {
				c.SkipTokenVerification = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "test",
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name:          "TestFailLoginWithBadPassword",
			ProxySettings: func(c *Config) {},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "notmypassword",
					},
					ExpectedCode: http.StatusUnauthorized,
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(c)
				newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestSkipOpenIDProviderTLSVerifyLoginHandler(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.SkipOpenIDProviderTLSVerify = true
	uri := c.WithOAuthURI(loginURL)
	requests := []fakeRequest{
		{
			URI:          uri,
			Method:       http.MethodPost,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          uri,
			Method:       http.MethodPost,
			FormValues:   map[string]string{"username": "test"},
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          uri,
			Method:       http.MethodPost,
			FormValues:   map[string]string{"password": "test"},
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:    uri,
			Method: http.MethodPost,
			FormValues: map[string]string{
				"password": "test",
				"username": "test",
			},
			ExpectedCode: http.StatusOK,
		},
		{
			URI:    uri,
			Method: http.MethodPost,
			FormValues: map[string]string{
				"password": "test",
				"username": "notmypassword",
			},
			ExpectedCode: http.StatusUnauthorized,
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

// nolint:funlen
func TestTokenEncryptionLoginHandler(t *testing.T) {
	c := newFakeKeycloakConfig()
	uri := c.WithOAuthURI(loginURL)

	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestEncryptedTokenEnabled",
			ProxySettings: func(c *Config) {
				c.EnableEncryptedToken = true
				c.ForceEncryptedCookie = false
				c.EnableLoginHandler = true
				c.Verbose = true
				c.EnableLogging = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "test",
					},
					ExpectedCookies: map[string]string{c.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *Config, string) bool{
						c.CookieAccessName: checkAccessTokenEncryption,
					},
					ExpectedContent: func(body string, testNum int) {
						resp := tokenResponse{}
						err := json.Unmarshal([]byte(body), &resp)
						require.NoError(t, err)
						assert.True(t, checkAccessTokenEncryption(t, c, resp.AccessToken))
						assert.True(t, checkRefreshTokenEncryption(t, c, resp.RefreshToken))
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestEncryptedTokenWithRefreshTokenEnabled",
			ProxySettings: func(c *Config) {
				c.EnableEncryptedToken = true
				c.ForceEncryptedCookie = false
				c.EnableLoginHandler = true
				c.Verbose = true
				c.EnableLogging = true
				c.EnableRefreshTokens = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "test",
					},
					ExpectedCookies: map[string]string{c.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *Config, string) bool{
						c.CookieAccessName:  checkAccessTokenEncryption,
						c.CookieRefreshName: checkRefreshTokenEncryption,
					},
					ExpectedContent: func(body string, testNum int) {
						resp := tokenResponse{}
						err := json.Unmarshal([]byte(body), &resp)
						require.NoError(t, err)
						assert.True(t, checkAccessTokenEncryption(t, c, resp.AccessToken))
						assert.True(t, checkRefreshTokenEncryption(t, c, resp.RefreshToken))
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestForceEncryptedCookie",
			ProxySettings: func(c *Config) {
				c.EnableEncryptedToken = false
				c.ForceEncryptedCookie = true
				c.EnableLoginHandler = true
				c.Verbose = true
				c.EnableLogging = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "test",
					},
					ExpectedCookies: map[string]string{c.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *Config, string) bool{
						c.CookieAccessName: checkAccessTokenEncryption,
					},
					ExpectedContent: func(body string, testNum int) {
						resp := tokenResponse{}
						err := json.Unmarshal([]byte(body), &resp)
						require.NoError(t, err)
						assert.False(t, checkAccessTokenEncryption(t, c, resp.AccessToken))
						assert.False(t, checkRefreshTokenEncryption(t, c, resp.RefreshToken))
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestForceEncryptedCookieWithRefreshToken",
			ProxySettings: func(c *Config) {
				c.EnableEncryptedToken = false
				c.ForceEncryptedCookie = true
				c.EnableLoginHandler = true
				c.Verbose = true
				c.EnableRefreshTokens = true
				c.EnableLogging = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "test",
					},
					ExpectedCookies: map[string]string{c.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *Config, string) bool{
						c.CookieAccessName:  checkAccessTokenEncryption,
						c.CookieRefreshName: checkRefreshTokenEncryption,
					},
					ExpectedContent: func(body string, testNum int) {
						resp := tokenResponse{}
						err := json.Unmarshal([]byte(body), &resp)
						require.NoError(t, err)
						assert.False(t, checkAccessTokenEncryption(t, c, resp.AccessToken))
						assert.False(t, checkRefreshTokenEncryption(t, c, resp.RefreshToken))
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestEncryptionDisabled",
			ProxySettings: func(c *Config) {
				c.EnableEncryptedToken = false
				c.ForceEncryptedCookie = false
				c.EnableLoginHandler = true
				c.Verbose = true
				c.EnableLogging = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "test",
					},
					ExpectedCookies: map[string]string{c.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *Config, string) bool{
						c.CookieAccessName: func(t *testing.T, config *Config, rawToken string) bool {
							token, err := jwt.ParseSigned(rawToken)
							if err != nil {
								return false
							}

							user, err := extractIdentity(token)

							if err != nil {
								return false
							}

							return assert.Contains(t, user.claims, "aud") && assert.Contains(t, user.claims, "email")
						},
					},
					ExpectedContent: func(body string, testNum int) {
						resp := tokenResponse{}
						err := json.Unmarshal([]byte(body), &resp)
						require.NoError(t, err)
						assert.False(t, checkAccessTokenEncryption(t, c, resp.AccessToken))
						assert.False(t, checkRefreshTokenEncryption(t, c, resp.RefreshToken))
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestEncryptionDisabledWithRefreshToken",
			ProxySettings: func(c *Config) {
				c.EnableEncryptedToken = false
				c.ForceEncryptedCookie = false
				c.EnableLoginHandler = true
				c.Verbose = true
				c.EnableRefreshTokens = true
				c.EnableLogging = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "test",
					},
					ExpectedCookies: map[string]string{c.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *Config, string) bool{
						c.CookieAccessName: func(t *testing.T, config *Config, rawToken string) bool {
							token, err := jwt.ParseSigned(rawToken)
							if err != nil {
								return false
							}

							user, err := extractIdentity(token)

							if err != nil {
								return false
							}

							return assert.Contains(t, user.claims, "aud") && assert.Contains(t, user.claims, "email")
						},
						c.CookieRefreshName: checkRefreshTokenEncryption,
					},
					ExpectedContent: func(body string, testNum int) {
						resp := tokenResponse{}
						err := json.Unmarshal([]byte(body), &resp)
						require.NoError(t, err)
						assert.False(t, checkAccessTokenEncryption(t, c, resp.AccessToken))
						assert.False(t, checkRefreshTokenEncryption(t, c, resp.RefreshToken))
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
				testCase.ProxySettings(c)
				newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestLogoutHandlerBadRequest(t *testing.T) {
	requests := []fakeRequest{
		{
			URI:          newFakeKeycloakConfig().WithOAuthURI(logoutURL),
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(nil, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestLogoutHandlerBadToken(t *testing.T) {
	c := newFakeKeycloakConfig()
	requests := []fakeRequest{
		{
			URI:          c.WithOAuthURI(logoutURL),
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:            c.WithOAuthURI(logoutURL),
			HasCookieToken: true,
			RawToken:       "this.is.a.bad.token",
			ExpectedCode:   http.StatusUnauthorized,
		},
		{
			URI:          c.WithOAuthURI(logoutURL),
			RawToken:     "this.is.a.bad.token",
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(nil, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestLogoutHandlerGood(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name:          "TestLogoutWithoutRedirect",
			ProxySettings: func(c *Config) {},
			ExecutionSettings: []fakeRequest{
				{
					URI:          cfg.WithOAuthURI(logoutURL),
					HasToken:     true,
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name:          "TestLogoutWithRedirectQueryParam",
			ProxySettings: func(c *Config) {},
			ExecutionSettings: []fakeRequest{
				{
					URI:              cfg.WithOAuthURI(logoutURL) + "?redirect=http://example.com",
					HasToken:         true,
					ExpectedCode:     http.StatusSeeOther,
					ExpectedLocation: "http://example.com",
				},
			},
		},
		{
			Name: "TestLogoutWithEnabledLogoutRedirectAndRedirectionURL",
			ProxySettings: func(c *Config) {
				c.RedirectionURL = "http://example.com"
				c.EnableLogoutRedirect = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:              cfg.WithOAuthURI(logoutURL),
					HasToken:         true,
					ExpectedCode:     http.StatusSeeOther,
					ExpectedLocation: "example.com",
				},
			},
		},
		{
			Name: "TestLogoutWithEnabledLogoutRedirectWithHostHeaders",
			ProxySettings: func(c *Config) {
				c.EnableLogoutRedirect = true
				c.RedirectionURL = ""
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:              cfg.WithOAuthURI(logoutURL),
					HasToken:         true,
					ExpectedCode:     http.StatusSeeOther,
					ExpectedLocation: "http://127.0.0.1",
				},
			},
		},
		{
			Name:          "TestLogoutWithEmptyRedirectQueryParam",
			ProxySettings: func(c *Config) {},
			ExecutionSettings: []fakeRequest{
				{
					URI:          cfg.WithOAuthURI(logoutURL) + "?redirect=",
					HasToken:     true,
					ExpectedCode: http.StatusSeeOther,
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
				proxy := newFakeProxy(c, &fakeAuthConfig{})
				testCase.ProxySettings(c)
				proxy.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestSkipOpenIDProviderTLSVerifyLogoutHandler(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.SkipOpenIDProviderTLSVerify = true
	requests := []fakeRequest{
		{
			URI:          c.WithOAuthURI(logoutURL),
			HasToken:     true,
			ExpectedCode: http.StatusOK,
		},
		{
			URI:              c.WithOAuthURI(logoutURL) + "?redirect=http://example.com",
			HasToken:         true,
			ExpectedCode:     http.StatusSeeOther,
			ExpectedLocation: "http://example.com",
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

func TestRevocation(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.RevocationEndpoint = ""
	requests := []fakeRequest{
		{
			URI:          c.WithOAuthURI(logoutURL),
			HasToken:     true,
			ExpectedCode: http.StatusOK,
		},
		{
			URI:              c.WithOAuthURI(logoutURL) + "?redirect=http://example.com",
			HasToken:         true,
			ExpectedCode:     http.StatusSeeOther,
			ExpectedLocation: "http://example.com",
		},
	}
	newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, requests)

	c.RevocationEndpoint = "http://non-existent.com/revoke"
	requests = []fakeRequest{
		{
			URI:          c.WithOAuthURI(logoutURL),
			HasToken:     true,
			ExpectedCode: http.StatusInternalServerError,
		},
		{
			URI:          c.WithOAuthURI(logoutURL) + "?redirect=http://example.com",
			HasToken:     true,
			ExpectedCode: http.StatusInternalServerError,
		},
	}
	newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestTokenHandler(t *testing.T) {
	uri := newFakeKeycloakConfig().WithOAuthURI(tokenURL)
	goodToken, err := newTestToken("example").getToken()

	if err != nil {
		t.Fatalf("Error when creating test token %v", err)
	}

	requests := []fakeRequest{
		{
			URI:          uri,
			HasToken:     true,
			RawToken:     goodToken,
			ExpectedCode: http.StatusOK,
			ExpectedContent: func(body string, testNum int) {
				assert.NotEqual(t, body, goodToken)
				jsonMap := make(map[string]interface{})
				err := json.Unmarshal([]byte(body), &jsonMap)
				require.NoError(t, err)
			},
		},
		{
			URI:          uri,
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:          uri,
			RawToken:     "niothing",
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:            uri,
			HasToken:       true,
			HasCookieToken: true,
			ExpectedCode:   http.StatusOK,
			ExpectedContent: func(body string, testNum int) {
				assert.NotEqual(t, body, goodToken)
				jsonMap := make(map[string]interface{})
				err := json.Unmarshal([]byte(body), &jsonMap)
				require.NoError(t, err)
			},
		},
	}
	newFakeProxy(nil, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestServiceRedirect(t *testing.T) {
	requests := []fakeRequest{
		{
			URI:              "/admin",
			Redirects:        true,
			ExpectedCode:     http.StatusSeeOther,
			ExpectedLocation: "/oauth/authorize?state",
		},
		{
			URI:          "/admin",
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(nil, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestAuthorizationURLWithSkipToken(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.SkipTokenVerification = true
	newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, []fakeRequest{
		{
			URI:          c.WithOAuthURI(authorizationURL),
			ExpectedCode: http.StatusNotAcceptable,
		},
	})
}

func TestAuthorizationURL(t *testing.T) {
	requests := []fakeRequest{
		{
			URI:              "/admin",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusSeeOther,
		},
		{
			URI:              "/admin/test",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusSeeOther,
		},
		{
			URI:              "/help/../admin",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusSeeOther,
		},
		{
			URI:              "/admin?test=yes&test1=test",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusSeeOther,
		},
		{
			URI:          "/oauth/test",
			Redirects:    true,
			ExpectedCode: http.StatusNotFound,
		},
		{
			URI:          "/oauth/callback/..//test",
			Redirects:    true,
			ExpectedCode: http.StatusNotFound,
		},
	}
	newFakeProxy(nil, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestCallbackURL(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	requests := []fakeRequest{
		{
			URI:          cfg.WithOAuthURI(callbackURL),
			Method:       http.MethodPost,
			ExpectedCode: http.StatusMethodNotAllowed,
		},
		{
			URI:          cfg.WithOAuthURI(callbackURL),
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:              cfg.WithOAuthURI(callbackURL) + "?code=fake",
			ExpectedCookies:  map[string]string{cfg.CookieAccessName: ""},
			ExpectedLocation: "/",
			ExpectedCode:     http.StatusSeeOther,
		},
		{
			URI:              cfg.WithOAuthURI(callbackURL) + "?code=fake&state=/admin",
			ExpectedCookies:  map[string]string{cfg.CookieAccessName: ""},
			ExpectedLocation: "/",
			ExpectedCode:     http.StatusSeeOther,
		},
		{
			URI:              cfg.WithOAuthURI(callbackURL) + "?code=fake&state=L2FkbWlu",
			ExpectedCookies:  map[string]string{cfg.CookieAccessName: ""},
			ExpectedLocation: "/",
			ExpectedCode:     http.StatusSeeOther,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestHealthHandler(t *testing.T) {
	c := newFakeKeycloakConfig()
	requests := []fakeRequest{
		{
			URI:          c.WithOAuthURI(healthURL),
			ExpectedCode: http.StatusOK,
			ExpectedContent: func(body string, testNum int) {
				assert.Equal(
					t, "OK\n", body,
					"case %d, expected content: %s, got: %s",
					testNum, "OK\n", body,
				)
			},
		},
		{
			URI:          c.WithOAuthURI(healthURL),
			Method:       http.MethodHead,
			ExpectedCode: http.StatusMethodNotAllowed,
		},
	}
	newFakeProxy(nil, &fakeAuthConfig{}).RunTests(t, requests)
}
