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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/keycloak/config"
	"github.com/stretchr/testify/assert"
)

func TestCookieDomainHostHeader(t *testing.T) {
	testCases := []struct {
		Name              string
		ProxySettings     func(cfg *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestCookieDomainDefaultEmpty",
			ProxySettings: func(conf *config.Config) {
				conf.EnableRefreshTokens = true
				conf.EncryptionKey = TestEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					OnResponse: func(int, *resty.Request, *resty.Response) {
						<-time.After(time.Duration(int64(2500)) * time.Millisecond)
					},
				},
				{
					URI:             FakeAuthAllURL,
					Redirects:       false,
					ExpectedProxy:   true,
					ExpectedCode:    http.StatusOK,
					ExpectedCookies: map[string]string{constant.AccessCookie: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *config.Config, *http.Cookie) bool{
						constant.AccessCookie: func(t *testing.T, _ *config.Config, cookie *http.Cookie) bool {
							t.Helper()
							notEmpty := assert.NotEmpty(t, cookie.Value)
							isDomainEmpty := assert.Empty(t, cookie.Domain)
							baseURIPath := assert.Equal(t, "/", cookie.Path)

							return notEmpty && isDomainEmpty && baseURIPath
						},
					},
				},
			},
		},
		{
			Name: "TestCookiePathWithBaseURIAndDomain",
			ProxySettings: func(conf *config.Config) {
				conf.EnableRefreshTokens = true
				conf.EncryptionKey = TestEncryptionKey
				conf.BaseURI = TestBaseURI
				conf.CookieDomain = "domain.com"
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					OnResponse: func(int, *resty.Request, *resty.Response) {
						<-time.After(time.Duration(int64(2500)) * time.Millisecond)
					},
				},
				{
					URI:             FakeAuthAllURL,
					Redirects:       false,
					ExpectedProxy:   true,
					ExpectedCode:    http.StatusOK,
					ExpectedCookies: map[string]string{constant.AccessCookie: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *config.Config, *http.Cookie) bool{
						constant.AccessCookie: func(t *testing.T, config *config.Config, cookie *http.Cookie) bool {
							t.Helper()
							notEmpty := assert.NotEmpty(t, cookie.Value)
							baseURIPath := assert.Equal(t, config.BaseURI, cookie.Path)
							cookieDomain := assert.Equal(t, config.CookieDomain, cookie.Domain)

							return notEmpty && baseURIPath && cookieDomain
						},
					},
				},
			},
		},
		{
			Name: "TestCookiePath",
			ProxySettings: func(conf *config.Config) {
				conf.EnableRefreshTokens = true
				conf.EncryptionKey = TestEncryptionKey
				conf.CookiePath = FakeAdminURL
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					OnResponse: func(int, *resty.Request, *resty.Response) {
						<-time.After(time.Duration(int64(2500)) * time.Millisecond)
					},
				},
				{
					URI:             FakeAuthAllURL,
					Redirects:       false,
					ExpectedProxy:   true,
					ExpectedCode:    http.StatusOK,
					ExpectedCookies: map[string]string{constant.AccessCookie: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *config.Config, *http.Cookie) bool{
						constant.AccessCookie: func(t *testing.T, _ *config.Config, cookie *http.Cookie) bool {
							t.Helper()
							notEmpty := assert.NotEmpty(t, cookie.Value)
							baseURIPath := assert.Equal(t, FakeAdminURL, cookie.Path)

							return notEmpty && baseURIPath
						},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				cfg := newFakeKeycloakConfig()
				testCase.ProxySettings(cfg)
				fProxy := newFakeProxy(cfg, &fakeAuthConfig{Expiration: 2000 * time.Millisecond})
				fProxy.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestDropCookie(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	fProxy := newFakeProxy(cfg, &fakeAuthConfig{})
	proxy := fProxy.proxy
	resp := httptest.NewRecorder()

	proxy.Cm.DropCookie(resp, "test-cookie", "test-value", 0)
	assert.Equal(t,
		"test-cookie=test-value; Path=/",
		resp.Header().Get(TestSetCookieHeader),
		"we have not set the cookie, headers: %v", resp.Header())

	resp = httptest.NewRecorder()
	proxy.Config.SecureCookie = false
	proxy.Cm.DropCookie(resp, "test-cookie", "test-value", 0)

	assert.Equal(t,
		"test-cookie=test-value; Path=/",
		resp.Header().Get(TestSetCookieHeader),
		"we have not set the cookie, headers: %v", resp.Header())

	resp = httptest.NewRecorder()
	proxy.Config.SecureCookie = true
	proxy.Cm.DropCookie(resp, "test-cookie", "test-value", 0)
	assert.NotEqual(t,
		"test-cookie=test-value; Path=/; HttpOnly; Secure",
		resp.Header().Get(TestSetCookieHeader),
		"we have not set the cookie, headers: %v", resp.Header())

	proxy.Config.CookieDomain = "test.com"
	proxy.Cm.DropCookie(resp, "test-cookie", "test-value", 0)
	proxy.Config.SecureCookie = false

	assert.NotEqual(t,
		"test-cookie=test-value; Path=/; Domain=test.com;",
		resp.Header().Get(TestSetCookieHeader),
		"we have not set the cookie, headers: %v", resp.Header())
}

func TestDropRefreshCookie(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	fProxy := newFakeProxy(cfg, &fakeAuthConfig{})
	proxy := fProxy.proxy

	req := newFakeHTTPRequest("GET", FakeAdminURL)
	resp := httptest.NewRecorder()
	proxy.Cm.DropRefreshTokenCookie(req, resp, "test", 0)

	assert.Equal(t,
		constant.RefreshCookie+"=test; Path=/",
		resp.Header().Get(TestSetCookieHeader),
		"we have not set the cookie, headers: %v", resp.Header())
}

func TestSessionOnlyCookie(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	fProxy := newFakeProxy(cfg, &fakeAuthConfig{})
	proxy := fProxy.proxy
	proxy.Cm.EnableSessionCookies = true

	resp := httptest.NewRecorder()
	proxy.Cm.DropCookie(resp, "test-cookie", "test-value", 1*time.Hour)

	assert.Equal(t,
		"test-cookie=test-value; Path=/",
		resp.Header().Get(TestSetCookieHeader),
		"we have not set the cookie, headers: %v", resp.Header())
}

func TestSameSiteCookie(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	fProxy := newFakeProxy(cfg, &fakeAuthConfig{})
	proxy := fProxy.proxy

	resp := httptest.NewRecorder()
	proxy.Cm.DropCookie(resp, "test-cookie", "test-value", 0)

	assert.Equal(t,
		"test-cookie=test-value; Path=/",
		resp.Header().Get(TestSetCookieHeader),
		"we have not set the cookie, headers: %v", resp.Header())

	resp = httptest.NewRecorder()
	proxy.Cm.SameSiteCookie = constant.SameSiteStrict
	proxy.Cm.DropCookie(resp, "test-cookie", "test-value", 0)

	assert.Equal(t,
		"test-cookie=test-value; Path=/; SameSite=Strict",
		resp.Header().Get(TestSetCookieHeader),
		"we have not set the cookie, headers: %v", resp.Header())

	resp = httptest.NewRecorder()
	proxy.Cm.SameSiteCookie = constant.SameSiteLax
	proxy.Cm.DropCookie(resp, "test-cookie", "test-value", 0)

	assert.Equal(t,
		"test-cookie=test-value; Path=/; SameSite=Lax",
		resp.Header().Get(TestSetCookieHeader),
		"we have not set the cookie, headers: %v", resp.Header())

	resp = httptest.NewRecorder()
	proxy.Cm.SameSiteCookie = constant.SameSiteNone
	proxy.Cm.DropCookie(resp, "test-cookie", "test-value", 0)

	assert.Equal(t,
		"test-cookie=test-value; Path=/; SameSite=None",
		resp.Header().Get(TestSetCookieHeader),
		"we have not set the cookie, headers: %v", resp.Header())
}

func TestHTTPOnlyCookie(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	fProxy := newFakeProxy(cfg, &fakeAuthConfig{})
	proxy := fProxy.proxy

	resp := httptest.NewRecorder()
	proxy.Cm.DropCookie(resp, "test-cookie", "test-value", 0)

	assert.Equal(t,
		"test-cookie=test-value; Path=/",
		resp.Header().Get(TestSetCookieHeader),
		"we have not set the cookie, headers: %v", resp.Header())

	resp = httptest.NewRecorder()
	proxy.Cm.HTTPOnlyCookie = true
	proxy.Cm.DropCookie(resp, "test-cookie", "test-value", 0)

	assert.Equal(t,
		"test-cookie=test-value; Path=/; HttpOnly",
		resp.Header().Get(TestSetCookieHeader),
		"we have not set the cookie, headers: %v", resp.Header())
}

func TestClearAccessTokenCookie(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	fProxy := newFakeProxy(cfg, &fakeAuthConfig{})
	proxy := fProxy.proxy

	req := newFakeHTTPRequest("GET", FakeAdminURL)
	req.Header.Set("Set-Cookie", constant.AccessCookie+"=; Path=/; Expires=")

	resp := httptest.NewRecorder()
	proxy.Cm.ClearAccessTokenCookie(req, resp)
	assert.Contains(t,
		resp.Header().Get(TestSetCookieHeader),
		constant.AccessCookie+"=; Path=/; Expires=",
		"we have not cleared the, headers: %v", resp.Header())
}

func TestClearRefreshAccessTokenCookie(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	fProxy := newFakeProxy(cfg, &fakeAuthConfig{})
	proxy := fProxy.proxy

	req := newFakeHTTPRequest("GET", FakeAdminURL)
	req.Header.Set("Set-Cookie", constant.RefreshCookie+"=; Path=/; Expires=")

	resp := httptest.NewRecorder()
	proxy.Cm.ClearRefreshTokenCookie(req, resp)
	assert.Contains(t,
		resp.Header().Get(TestSetCookieHeader),
		constant.RefreshCookie+"=; Path=/; Expires=",
		"we have not cleared the, headers: %v", resp.Header())
}

func TestClearAllCookies(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	fProxy := newFakeProxy(cfg, &fakeAuthConfig{})
	proxy := fProxy.proxy

	req := newFakeHTTPRequest("GET", FakeAdminURL)
	req.Header.Set("Set-Cookie", constant.RefreshCookie+"=; Path=/; Expires=")
	req.Header.Set("Set-Cookie", constant.AccessCookie+"=; Path=/; Expires=")

	resp := httptest.NewRecorder()
	proxy.Cm.ClearAllCookies(req, resp)
	assert.Contains(t,
		resp.Header().Get(TestSetCookieHeader),
		constant.AccessCookie+"=; Path=/; Expires=",
		"we have not cleared the, headers: %v", resp.Header())
}

func TestGetMaxCookieChunkLength(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	fProxy := newFakeProxy(cfg, &fakeAuthConfig{})
	proxy := fProxy.proxy

	req := newFakeHTTPRequest("GET", FakeAdminURL)

	proxy.Cm.HTTPOnlyCookie = true
	proxy.Cm.EnableSessionCookies = true
	proxy.Cm.SecureCookie = true
	proxy.Cm.SameSiteCookie = "Strict"
	proxy.Cm.CookieDomain = "1234567890"
	assert.Equal(t, 4017, proxy.Cm.GetMaxCookieChunkLength(req, "1234567890"),
		"cookie chunk calculation is not correct")

	proxy.Cm.SameSiteCookie = "Lax"
	assert.Equal(t, 4020, proxy.Cm.GetMaxCookieChunkLength(req, "1234567890"),
		"cookie chunk calculation is not correct")

	proxy.Cm.HTTPOnlyCookie = false
	proxy.Cm.EnableSessionCookies = false
	proxy.Cm.SecureCookie = false
	proxy.Cm.SameSiteCookie = "None"
	proxy.Cm.CookieDomain = ""
	assert.Equal(t, 4007, proxy.Cm.GetMaxCookieChunkLength(req, ""),
		"cookie chunk calculation is not correct")
}

func TestCustomCookieNames(t *testing.T) {
	customStateName := "customState"
	customRedirectName := "customRedirect"
	customAccessName := "customAccess"
	customRefreshName := "customRefresh"
	customPKCEName := "customPKCE"
	customIDTokenName := "customID"

	testCases := []struct {
		Name              string
		ProxySettings     func(cfg *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestCustomStateCookiePresent",
			ProxySettings: func(cfg *config.Config) {
				cfg.Verbose = true
				cfg.EnableLogging = true
				cfg.CookieOAuthStateName = customStateName
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						customStateName: func(t *testing.T, _ *config.Config, value string) bool {
							t.Helper()
							return assert.NotEmpty(t, value)
						},
					},
				},
			},
		},
		{
			Name: "TestCustomAccessCookiePresent",
			ProxySettings: func(cfg *config.Config) {
				cfg.Verbose = true
				cfg.EnableLogging = true
				cfg.CookieAccessName = customAccessName
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						customAccessName: func(t *testing.T, _ *config.Config, value string) bool {
							t.Helper()
							return assert.NotEmpty(t, value)
						},
					},
				},
			},
		},
		{
			Name: "TestCustomRefreshCookiePresent",
			ProxySettings: func(cfg *config.Config) {
				cfg.Verbose = true
				cfg.EnableLogging = true
				cfg.EnableRefreshTokens = true
				cfg.CookieRefreshName = customRefreshName
				cfg.EncryptionKey = TestEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						customRefreshName: func(t *testing.T, _ *config.Config, value string) bool {
							t.Helper()
							return assert.NotEmpty(t, value)
						},
					},
				},
			},
		},
		{
			Name: "TestCustomRedirectUriCookiePresent",
			ProxySettings: func(cfg *config.Config) {
				cfg.Verbose = true
				cfg.EnableLogging = true
				cfg.CookieOAuthStateName = customStateName
				cfg.CookieRequestURIName = customRedirectName
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						customRedirectName: func(t *testing.T, _ *config.Config, value string) bool {
							t.Helper()
							return assert.NotEmpty(t, value)
						},
					},
				},
			},
		},
		{
			Name: "TestCustomPKCECookiePresent",
			ProxySettings: func(cfg *config.Config) {
				cfg.Verbose = true
				cfg.EnableLogging = true
				cfg.EnablePKCE = true
				cfg.CookieOAuthStateName = customStateName
				cfg.CookiePKCEName = customPKCEName
				cfg.CookieRequestURIName = customRedirectName
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						customPKCEName: func(t *testing.T, _ *config.Config, value string) bool {
							t.Helper()
							return assert.NotEmpty(t, value)
						},
					},
				},
			},
		},
		{
			Name: "TestCustomIDTokenCookiePresent",
			ProxySettings: func(cfg *config.Config) {
				cfg.Verbose = true
				cfg.EnableLogging = true
				cfg.CookieOAuthStateName = customStateName
				cfg.CookieRequestURIName = customRedirectName
				cfg.CookieIDTokenName = customIDTokenName
				cfg.CookieAccessName = customAccessName
				cfg.EnableIDTokenCookie = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						customIDTokenName: func(t *testing.T, _ *config.Config, value string) bool {
							t.Helper()
							return assert.NotEmpty(t, value)
						},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				cfg := newFakeKeycloakConfig()
				testCase.ProxySettings(cfg)
				fProxy := newFakeProxy(
					cfg,
					&fakeAuthConfig{
						EnablePKCE: cfg.EnablePKCE,
					},
				)
				fProxy.idp.setTokenExpiration(90 * time.Second)
				fProxy.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}
