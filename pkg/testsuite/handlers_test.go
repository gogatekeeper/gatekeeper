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

package testsuite

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/keycloak/config"
	"github.com/gogatekeeper/gatekeeper/pkg/keycloak/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDebugHandler(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = make([]*authorization.Resource, 0)
	cfg.EnableProfiling = true
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
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestExpirationHandler(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	uri := proxy.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.ExpiredURL)
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
	cfg := newFakeKeycloakConfig()
	cfg.EnableLoginHandler = false
	loginURL := proxy.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.LoginURL)
	requests := []fakeRequest{
		{URI: loginURL, Method: http.MethodPost, ExpectedCode: http.StatusNotImplemented},
		{URI: loginURL, ExpectedCode: http.StatusMethodNotAllowed},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestLoginHandlerNotDisabled(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableLoginHandler = true
	requests := []fakeRequest{
		{URI: "/oauth/login", Method: http.MethodPost, ExpectedCode: http.StatusBadRequest},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestLoginHandler(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	uri := proxy.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.LoginURL)

	testCases := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name:          "TestFailLoginWithoutCredentials",
			ProxySettings: func(c *config.Config) {},
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
			ProxySettings: func(c *config.Config) {},
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
			ProxySettings: func(c *config.Config) {},
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
			ProxySettings: func(c *config.Config) {},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "test",
					},
					ExpectedContent: func(body string, testNum int) {
						resp := proxy.TokenResponse{}
						err := json.Unmarshal([]byte(body), &resp)
						require.NoError(t, err)
						assert.Equal(t, "Bearer", resp.TokenType)
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestLoginWithSkipTokenVerification",
			ProxySettings: func(c *config.Config) {
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
			ProxySettings: func(c *config.Config) {},
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

func TestSkipOpenIDProviderTLSVerifyLoginHandler(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.SkipOpenIDProviderTLSVerify = true
	uri := proxy.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.LoginURL)
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
	newFakeProxy(cfg, &fakeAuthConfig{EnableTLS: true}).RunTests(t, requests)

	cfg.SkipOpenIDProviderTLSVerify = false

	defer func() {
		if r := recover(); r != nil {
			failure, assertOk := r.(string)

			if !assertOk {
				t.Fatalf(apperrors.ErrAssertionFailed.Error())
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

//nolint:funlen
func TestTokenEncryptionLoginHandler(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	uri := proxy.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.LoginURL)
	// !! it must be here because of how test is written
	cfg.EncryptionKey = testEncryptionKey

	testCases := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestEncryptedTokenEnabled",
			ProxySettings: func(conf *config.Config) {
				conf.EnableEncryptedToken = true
				conf.ForceEncryptedCookie = false
				conf.EnableLoginHandler = true
				conf.Verbose = true
				conf.EnableLogging = true
				conf.EncryptionKey = testEncryptionKey
				conf.EnableIDTokenCookie = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "test",
					},
					ExpectedCookies: map[string]string{
						cfg.CookieAccessName:  "",
						cfg.CookieIDTokenName: "",
					},
					ExpectedCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieAccessName:  checkAccessTokenEncryption,
						cfg.CookieIDTokenName: checkAccessTokenEncryption,
					},
					ExpectedContent: func(body string, testNum int) {
						resp := proxy.TokenResponse{}
						err := json.Unmarshal([]byte(body), &resp)
						require.NoError(t, err)
						assert.True(t, checkAccessTokenEncryption(t, cfg, resp.AccessToken))
						assert.True(t, checkAccessTokenEncryption(t, cfg, resp.IDToken))
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestEncryptedTokenWithRefreshTokenEnabled",
			ProxySettings: func(conf *config.Config) {
				conf.EnableEncryptedToken = true
				conf.ForceEncryptedCookie = false
				conf.EnableLoginHandler = true
				conf.Verbose = true
				conf.EnableLogging = true
				conf.EnableRefreshTokens = true
				conf.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "test",
					},
					ExpectedCookies: map[string]string{cfg.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieAccessName:  checkAccessTokenEncryption,
						cfg.CookieRefreshName: checkRefreshTokenEncryption,
					},
					ExpectedContent: func(body string, testNum int) {
						resp := proxy.TokenResponse{}
						err := json.Unmarshal([]byte(body), &resp)
						require.NoError(t, err)
						assert.True(t, checkAccessTokenEncryption(t, cfg, resp.AccessToken))
						assert.True(t, checkRefreshTokenEncryption(t, cfg, resp.RefreshToken))
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestForceEncryptedCookie",
			ProxySettings: func(conf *config.Config) {
				conf.EnableEncryptedToken = false
				conf.ForceEncryptedCookie = true
				conf.EnableLoginHandler = true
				conf.Verbose = true
				conf.EnableLogging = true
				conf.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "test",
					},
					ExpectedCookies: map[string]string{cfg.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieAccessName: checkAccessTokenEncryption,
					},
					ExpectedContent: func(body string, testNum int) {
						resp := proxy.TokenResponse{}
						err := json.Unmarshal([]byte(body), &resp)
						require.NoError(t, err)
						assert.False(t, checkAccessTokenEncryption(t, cfg, resp.AccessToken))
						assert.False(t, checkRefreshTokenEncryption(t, cfg, resp.RefreshToken))
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestForceEncryptedCookieWithRefreshToken",
			ProxySettings: func(conf *config.Config) {
				conf.EnableEncryptedToken = false
				conf.ForceEncryptedCookie = true
				conf.EnableLoginHandler = true
				conf.Verbose = true
				conf.EnableRefreshTokens = true
				conf.EnableLogging = true
				conf.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "test",
					},
					ExpectedCookies: map[string]string{cfg.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieAccessName:  checkAccessTokenEncryption,
						cfg.CookieRefreshName: checkRefreshTokenEncryption,
					},
					ExpectedContent: func(body string, testNum int) {
						resp := proxy.TokenResponse{}
						err := json.Unmarshal([]byte(body), &resp)
						require.NoError(t, err)
						assert.False(t, checkAccessTokenEncryption(t, cfg, resp.AccessToken))
						assert.True(t, checkRefreshTokenEncryption(t, cfg, resp.RefreshToken))
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestEncryptionDisabled",
			ProxySettings: func(conf *config.Config) {
				conf.EnableEncryptedToken = false
				conf.ForceEncryptedCookie = false
				conf.EnableLoginHandler = true
				conf.Verbose = true
				conf.EnableLogging = true
				conf.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "test",
					},
					ExpectedCookies: map[string]string{cfg.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieAccessName: func(t *testing.T, config *config.Config, rawToken string) bool {
							token, err := jwt.ParseSigned(rawToken)
							if err != nil {
								return false
							}

							user, err := proxy.ExtractIdentity(token)

							if err != nil {
								return false
							}

							return assert.Contains(t, user.Claims, "aud") && assert.Contains(t, user.Claims, "email")
						},
					},
					ExpectedContent: func(body string, testNum int) {
						resp := proxy.TokenResponse{}
						err := json.Unmarshal([]byte(body), &resp)
						require.NoError(t, err)
						assert.False(t, checkAccessTokenEncryption(t, cfg, resp.AccessToken))
						assert.False(t, checkRefreshTokenEncryption(t, cfg, resp.RefreshToken))
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestEncryptionDisabledWithRefreshToken",
			ProxySettings: func(conf *config.Config) {
				conf.EnableEncryptedToken = false
				conf.ForceEncryptedCookie = false
				conf.EnableLoginHandler = true
				conf.Verbose = true
				conf.EnableRefreshTokens = true
				conf.EnableLogging = true
				conf.EncryptionKey = testEncryptionKey
				conf.EnableIDTokenCookie = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:    uri,
					Method: http.MethodPost,
					FormValues: map[string]string{
						"password": "test",
						"username": "test",
					},
					ExpectedCookies: map[string]string{
						cfg.CookieAccessName:  "",
						cfg.CookieIDTokenName: "",
					},
					ExpectedCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieAccessName: func(t *testing.T, config *config.Config, rawToken string) bool {
							token, err := jwt.ParseSigned(rawToken)
							if err != nil {
								return false
							}

							user, err := proxy.ExtractIdentity(token)

							if err != nil {
								return false
							}

							return assert.Contains(t, user.Claims, "aud") && assert.Contains(t, user.Claims, "email")
						},
						cfg.CookieRefreshName: checkRefreshTokenEncryption,
					},
					ExpectedContent: func(body string, testNum int) {
						resp := proxy.TokenResponse{}
						err := json.Unmarshal([]byte(body), &resp)
						require.NoError(t, err)
						assert.False(t, checkAccessTokenEncryption(t, cfg, resp.AccessToken))
						assert.False(t, checkAccessTokenEncryption(t, cfg, resp.IDToken))
						assert.True(t, checkRefreshTokenEncryption(t, cfg, resp.RefreshToken))
					},
					ExpectedCode: http.StatusOK,
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
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

func TestLogoutHandlerBadRequest(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	logoutURL := proxy.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.LogoutURL)
	requests := []fakeRequest{
		{
			URI:          logoutURL,
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(nil, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestLogoutHandlerBadToken(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	logoutURL := proxy.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.LogoutURL)
	requests := []fakeRequest{
		{
			URI:          logoutURL,
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:            logoutURL,
			HasCookieToken: true,
			RawToken:       "this.is.a.bad.token",
			ExpectedCode:   http.StatusUnauthorized,
		},
		{
			URI:          logoutURL,
			RawToken:     "this.is.a.bad.token",
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(nil, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestLogoutHandlerGood(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	logoutURL := proxy.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.LogoutURL)
	testCases := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name:          "TestLogoutWithoutRedirect",
			ProxySettings: func(c *config.Config) {},
			ExecutionSettings: []fakeRequest{
				{
					URI:          logoutURL,
					HasToken:     true,
					ExpectedCode: http.StatusOK,
				},
			},
		},
		// {
		// 	Name:          "TestLogoutWithRedirectQueryParam",
		// 	ProxySettings: func(c *config.Config) {},
		// 	ExecutionSettings: []fakeRequest{
		// 		{
		// 			URI:              cfg.WithOAuthURI(constant.LogoutURL) + "?redirect=http://example.com",
		// 			HasToken:         true,
		// 			ExpectedCode:     http.StatusSeeOther,
		// 			ExpectedLocation: "http://example.com",
		// 		},
		// 	},
		// },
		// {
		// 	Name: "TestLogoutWithEnabledLogoutRedirect",
		// 	ProxySettings: func(c *config.Config) {
		// 		c.EnableLogoutRedirect = true
		// 	},
		// 	ExecutionSettings: []fakeRequest{
		// 		{
		// 			URI:              cfg.WithOAuthURI(constant.LogoutURL),
		// 			HasToken:         true,
		// 			ExpectedCode:     http.StatusSeeOther,
		// 			ExpectedLocation: "http://127.0.0.1",
		// 		},
		// 	},
		// },
		// {
		// 	Name:          "TestLogoutWithEmptyRedirectQueryParam",
		// 	ProxySettings: func(c *config.Config) {},
		// 	ExecutionSettings: []fakeRequest{
		// 		{
		// 			URI:          cfg.WithOAuthURI(constant.LogoutURL) + "?redirect=",
		// 			HasToken:     true,
		// 			ExpectedCode: http.StatusSeeOther,
		// 		},
		// 	},
		// },
	}

	for _, testCase := range testCases {
		testCase := testCase
		cfgCopy := *cfg
		cfg := &cfgCopy
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(cfg)
				proxy := newFakeProxy(cfg, &fakeAuthConfig{})
				testCase.ProxySettings(cfg)
				proxy.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestSkipOpenIDProviderTLSVerifyLogoutHandler(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.SkipOpenIDProviderTLSVerify = true
	logoutURL := proxy.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.LogoutURL)
	requests := []fakeRequest{
		{
			URI:          logoutURL,
			HasToken:     true,
			ExpectedCode: http.StatusOK,
		},
		{
			URI:              logoutURL + "?redirect=http://example.com",
			HasToken:         true,
			ExpectedCode:     http.StatusSeeOther,
			ExpectedLocation: "http://example.com",
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{EnableTLS: true}).RunTests(t, requests)

	cfg.SkipOpenIDProviderTLSVerify = false

	defer func() {
		if r := recover(); r != nil {
			failure, assertOk := r.(string)

			if !assertOk {
				t.Fatalf(apperrors.ErrAssertionFailed.Error())
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

func TestRevocation(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.RevocationEndpoint = ""
	logoutURL := proxy.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.LogoutURL)
	requests := []fakeRequest{
		{
			URI:          logoutURL,
			HasToken:     true,
			ExpectedCode: http.StatusOK,
		},
		{
			URI:              logoutURL + "?redirect=http://example.com",
			HasToken:         true,
			ExpectedCode:     http.StatusSeeOther,
			ExpectedLocation: "http://example.com",
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)

	cfg.RevocationEndpoint = "http://non-existent.com/revoke"
	requests = []fakeRequest{
		{
			URI:          logoutURL,
			HasToken:     true,
			ExpectedCode: http.StatusInternalServerError,
		},
		{
			URI:          logoutURL + "?redirect=http://example.com",
			HasToken:     true,
			ExpectedCode: http.StatusInternalServerError,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestTokenHandler(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	uri := proxy.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.TokenURL)
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
	cfg := newFakeKeycloakConfig()
	cfg.SkipTokenVerification = true
	uri := proxy.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.AuthorizationURL)
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, []fakeRequest{
		{
			URI:          uri,
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
	uri := proxy.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.CallbackURL)
	requests := []fakeRequest{
		{
			URI:          uri,
			Method:       http.MethodPost,
			ExpectedCode: http.StatusMethodNotAllowed,
		},
		{
			URI:          uri,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:              uri + "?code=fake",
			ExpectedCookies:  map[string]string{cfg.CookieAccessName: ""},
			ExpectedLocation: "/",
			ExpectedCode:     http.StatusSeeOther,
		},
		{
			URI:              uri + "?code=fake&state=/admin",
			ExpectedCookies:  map[string]string{cfg.CookieAccessName: ""},
			ExpectedLocation: "/",
			ExpectedCode:     http.StatusSeeOther,
		},
		{
			URI:              uri + "?code=fake&state=L2FkbWlu",
			ExpectedCookies:  map[string]string{cfg.CookieAccessName: ""},
			ExpectedLocation: "/",
			ExpectedCode:     http.StatusSeeOther,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestHealthHandler(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	uri := proxy.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.HealthURL)
	requests := []fakeRequest{
		{
			URI:          uri,
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
			URI:          uri,
			Method:       http.MethodHead,
			ExpectedCode: http.StatusMethodNotAllowed,
		},
	}
	newFakeProxy(nil, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestDiscoveryURL(t *testing.T) {
	testCases := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name:          "TestDiscoveryOK",
			ProxySettings: func(c *config.Config) {},
			ExecutionSettings: []fakeRequest{
				{
					URI:                     "/oauth/discovery",
					ExpectedProxy:           false,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "logout_endpoint",
				},
			},
		},
		{
			Name: "TestWithDefaultDenyDiscoveryOK",
			ProxySettings: func(c *config.Config) {
				c.EnableDefaultDeny = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                     "/oauth/discovery",
					ExpectedProxy:           false,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "login_endpoint",
				},
			},
		},
		{
			Name: "TestWithDefaultDenyStrictDiscoveryOK",
			ProxySettings: func(c *config.Config) {
				c.EnableDefaultDenyStrict = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                     "/oauth/discovery",
					ExpectedProxy:           false,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "login_endpoint",
				},
			},
		},
		{
			Name: "TestEndpointPathCorrectWithDefaultDenyDiscoveryOK",
			ProxySettings: func(c *config.Config) {
				c.EnableDefaultDeny = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                     "/oauth/discovery",
					ExpectedProxy:           false,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "/oauth/login",
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
