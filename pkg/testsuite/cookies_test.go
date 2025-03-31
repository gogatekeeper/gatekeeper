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

	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/keycloak/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCookieDomainHostHeader(t *testing.T) {
	svc := newTestService()
	resp, _, err := makeTestCodeFlowLogin(svc+FakeAdminURL, false)
	require.NoError(t, err)
	assert.NotNil(t, resp)

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == constant.AccessCookie {
			cookie = c
		}
	}
	defer resp.Body.Close()

	assert.NotNil(t, cookie)
	assert.Empty(t, cookie.Domain)
}

func TestCookieBasePath(t *testing.T) {
	const baseURI = "/base-uri"
	cfg := newFakeKeycloakConfig()
	cfg.BaseURI = baseURI

	_, _, svc := newTestProxyService(cfg)

	resp, _, err := makeTestCodeFlowLogin(svc+FakeAdminURL, false)
	require.NoError(t, err)
	assert.NotNil(t, resp)

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == constant.AccessCookie {
			cookie = c
		}
	}
	defer resp.Body.Close()

	assert.NotNil(t, cookie)
	assert.Equal(t, baseURI, cookie.Path)
}

func TestCookieWithoutBasePath(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	_, _, svc := newTestProxyService(cfg)

	resp, _, err := makeTestCodeFlowLogin(svc+FakeAdminURL, false)
	require.NoError(t, err)
	assert.NotNil(t, resp)

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == constant.AccessCookie {
			cookie = c
		}
	}
	defer resp.Body.Close()

	assert.NotNil(t, cookie)
	assert.Equal(t, "/", cookie.Path)
}

func TestCookieDomain(t *testing.T) {
	p, _, svc := newTestProxyService(nil)
	p.Cm.CookieDomain = "domain.com"
	resp, _, err := makeTestCodeFlowLogin(svc+FakeAdminURL, false)
	require.NoError(t, err)
	assert.NotNil(t, resp)

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == constant.AccessCookie {
			cookie = c
		}
	}
	defer resp.Body.Close()

	assert.NotNil(t, cookie)
	assert.Equal(t, "domain.com", cookie.Domain)
}

func TestCookiePath(t *testing.T) {
	p, _, svc := newTestProxyService(nil)
	p.Cm.CookiePath = FakeAdminURL
	resp, _, err := makeTestCodeFlowLogin(svc+FakeAdminURL, false)
	require.NoError(t, err)
	assert.NotNil(t, resp)

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Path == FakeAdminURL {
			cookie = c
		}
	}
	defer resp.Body.Close()

	assert.NotNil(t, cookie)
	assert.Equal(t, FakeAdminURL, cookie.Path)
}

func TestDropCookie(t *testing.T) {
	proxy, _, _ := newTestProxyService(nil)

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
	p, _, _ := newTestProxyService(nil)

	req := newFakeHTTPRequest("GET", FakeAdminURL)
	resp := httptest.NewRecorder()
	p.Cm.DropRefreshTokenCookie(req, resp, "test", 0)

	assert.Equal(t,
		constant.RefreshCookie+"=test; Path=/",
		resp.Header().Get(TestSetCookieHeader),
		"we have not set the cookie, headers: %v", resp.Header())
}

func TestSessionOnlyCookie(t *testing.T) {
	p, _, _ := newTestProxyService(nil)
	p.Cm.EnableSessionCookies = true

	resp := httptest.NewRecorder()
	p.Cm.DropCookie(resp, "test-cookie", "test-value", 1*time.Hour)

	assert.Equal(t,
		"test-cookie=test-value; Path=/",
		resp.Header().Get(TestSetCookieHeader),
		"we have not set the cookie, headers: %v", resp.Header())
}

func TestSameSiteCookie(t *testing.T) {
	proxy, _, _ := newTestProxyService(nil)

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
	proxy, _, _ := newTestProxyService(nil)

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
	proxy, _, _ := newTestProxyService(nil)

	req := newFakeHTTPRequest("GET", FakeAdminURL)
	resp := httptest.NewRecorder()
	proxy.Cm.ClearAccessTokenCookie(req, resp)
	assert.Contains(t,
		resp.Header().Get(TestSetCookieHeader),
		constant.AccessCookie+"=; Path=/; Expires=",
		"we have not cleared the, headers: %v", resp.Header())
}

func TestClearRefreshAccessTokenCookie(t *testing.T) {
	p, _, _ := newTestProxyService(nil)
	req := newFakeHTTPRequest("GET", FakeAdminURL)
	resp := httptest.NewRecorder()
	p.Cm.ClearRefreshTokenCookie(req, resp)
	assert.Contains(t,
		resp.Header().Get(TestSetCookieHeader),
		constant.RefreshCookie+"=; Path=/; Expires=",
		"we have not cleared the, headers: %v", resp.Header())
}

func TestClearAllCookies(t *testing.T) {
	p, _, _ := newTestProxyService(nil)
	req := newFakeHTTPRequest("GET", FakeAdminURL)
	resp := httptest.NewRecorder()
	p.Cm.ClearAllCookies(req, resp)
	assert.Contains(t,
		resp.Header().Get(TestSetCookieHeader),
		constant.AccessCookie+"=; Path=/; Expires=",
		"we have not cleared the, headers: %v", resp.Header())
}

func TestGetMaxCookieChunkLength(t *testing.T) {
	proxy, _, _ := newTestProxyService(nil)
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
				cfg.EncryptionKey = testEncryptionKey
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
