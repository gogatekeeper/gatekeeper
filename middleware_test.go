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
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	resty "github.com/go-resty/resty/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/storage"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"github.com/rs/cors"
	"github.com/stretchr/testify/assert"

	"gopkg.in/square/go-jose.v2/jwt"
)

func TestMetricsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableMetrics = true
	cfg.LocalhostMetrics = true
	cfg.EnableRefreshTokens = true
	cfg.EnableEncryptedToken = true
	cfg.EncryptionKey = testEncryptionKey
	requests := []fakeRequest{
		{
			URI:       fakeAuthAllURL,
			HasLogin:  true,
			Redirects: true,
			OnResponse: func(int, *resty.Request, *resty.Response) {
				<-time.After(time.Duration(int64(2500)) * time.Millisecond)
			},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           fakeAuthAllURL,
			Redirects:     false,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI: cfg.WithOAuthURI(constant.MetricsURL),
			Headers: map[string]string{
				"X-Forwarded-For": "10.0.0.1",
			},
			ExpectedCode: http.StatusForbidden,
		},
		// Some request must run before this one to generate request status numbers
		{
			URI:                     cfg.WithOAuthURI(constant.MetricsURL),
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "proxy_request_status_total",
		},
		{
			URI:                     cfg.WithOAuthURI(constant.MetricsURL),
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "action=\"issued\"",
		},
		{
			URI:                     cfg.WithOAuthURI(constant.MetricsURL),
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "action=\"exchange\"",
		},
		{
			URI:                     cfg.WithOAuthURI(constant.MetricsURL),
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "action=\"renew\"",
		},
	}
	p := newFakeProxy(cfg, &fakeAuthConfig{})
	p.idp.setTokenExpiration(2000 * time.Millisecond)
	p.RunTests(t, requests)
}

func TestOauthRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	requests := []fakeRequest{
		{
			URI:          "/oauth/authorize",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{
			URI:          "/oauth/callback",
			Redirects:    true,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          "/oauth/health",
			Redirects:    true,
			ExpectedCode: http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

//nolint:cyclop
func TestAdminListener(t *testing.T) {
	testCases := []struct {
		Name              string
		ProxySettings     func(conf *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestAdminOnSameListener",
			ProxySettings: func(conf *Config) {
				conf.EnableMetrics = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                     "/oauth/health",
					Redirects:               true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "OK",
				},
				{
					URI:          "/oauth/metrics",
					Redirects:    true,
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestAdminOnDifferentListener",
			ProxySettings: func(conf *Config) {
				conf.EnableMetrics = true
				conf.ListenAdmin = "127.0.0.1:12300"
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:          "/oauth/health",
					Redirects:    true,
					ExpectedCode: http.StatusNotFound,
				},
				{
					URI:          "/oauth/metrics",
					Redirects:    true,
					ExpectedCode: http.StatusNotFound,
				},
				{
					URL:                     "http://127.0.0.1:12300/oauth/health",
					Redirects:               true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "OK",
				},
				{
					URL:          "http://127.0.0.1:12300/oauth/metrics",
					Redirects:    true,
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestAdminOnDifferentListenerWithHTTPS",
			ProxySettings: func(conf *Config) {
				conf.EnableMetrics = true
				conf.ListenAdmin = "127.0.0.1:12301"
				conf.ListenAdminScheme = constant.SecureScheme
				conf.TLSAdminCertificate = fmt.Sprintf(os.TempDir()+"/gateadmin_crt_%d", rand.Intn(10000))
				conf.TLSAdminPrivateKey = fmt.Sprintf(os.TempDir()+"/gateadmin_priv_%d", rand.Intn(10000))
				conf.TLSAdminCaCertificate = fmt.Sprintf(os.TempDir()+"/gateadmin_ca_%d", rand.Intn(10000))
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     "https://127.0.0.1:12301/oauth/health",
					Redirects:               true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "OK",
					RequestCA:               fakeCA,
				},
				{
					URL:          "https://127.0.0.1:12301/oauth/metrics",
					Redirects:    true,
					ExpectedCode: http.StatusOK,
					RequestCA:    fakeCA,
				},
			},
		},
		{
			Name: "TestAdminOnDifferentListenerWithHTTPSandCommonCreds",
			ProxySettings: func(conf *Config) {
				conf.EnableMetrics = true
				conf.ListenAdmin = "127.0.0.1:12302"
				conf.ListenAdminScheme = constant.SecureScheme
				conf.TLSCertificate = fmt.Sprintf(os.TempDir()+"/gateadmin_crt_%d", rand.Intn(10000))
				conf.TLSPrivateKey = fmt.Sprintf(os.TempDir()+"/gateadmin_priv_%d", rand.Intn(10000))
				conf.TLSCaCertificate = fmt.Sprintf(os.TempDir()+"/gateadmin_ca_%d", rand.Intn(10000))
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     "https://127.0.0.1:12302/oauth/health",
					Redirects:               true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "OK",
					RequestCA:               fakeCA,
				},
				{
					URL:          "https://127.0.0.1:12302/oauth/metrics",
					Redirects:    true,
					ExpectedCode: http.StatusOK,
					RequestCA:    fakeCA,
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

				if cfg.TLSAdminCertificate != "" {
					certFile = cfg.TLSAdminCertificate
				}

				if cfg.TLSCertificate != "" {
					certFile = cfg.TLSCertificate
				}

				if cfg.TLSAdminPrivateKey != "" {
					privFile = cfg.TLSAdminPrivateKey
				}

				if cfg.TLSPrivateKey != "" {
					privFile = cfg.TLSPrivateKey
				}

				if cfg.TLSAdminCaCertificate != "" {
					caFile = cfg.TLSAdminCaCertificate
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

func TestOauthRequestsWithBaseURI(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.BaseURI = "/base-uri"
	requests := []fakeRequest{
		{
			URI:          "/base-uri/oauth/authorize",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{
			URI:          "/base-uri/oauth/callback",
			Redirects:    true,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          "/base-uri/oauth/health",
			Redirects:    true,
			ExpectedCode: http.StatusOK,
		},
		{
			URI:           "/oauth/authorize",
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/oauth/callback",
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/oauth/health",
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestMethodExclusions(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/post",
			Methods: []string{http.MethodPost, http.MethodPut},
		},
	}
	requests := []fakeRequest{
		{ // we should get a 401
			URI:          "/post",
			Method:       http.MethodPost,
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // we should be permitted
			URI:           "/post",
			Method:        http.MethodGet,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestPreserveURLEncoding(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableLogging = true
	cfg.Resources = []*Resource{
		{
			URL:     "/api/v2/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"dev"},
		},
		{
			URL:     "/api/v1/auth*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"admin"},
		},
		{
			URL:         "/api/v1/*",
			Methods:     utils.AllHTTPMethods,
			WhiteListed: true,
		},
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"user"},
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/test",
			HasToken:     true,
			Roles:        []string{"nothing"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // See KEYCLOAK-10864
			URI:                     "/administrativeMonitor/hudson.diagnosis.ReverseProxySetupMonitor/testForReverseProxySetup/https%3A%2F%2Flocalhost%3A6001%2Fmanage/",
			ExpectedContentContains: `"uri":"/administrativeMonitor/hudson.diagnosis.ReverseProxySetupMonitor/testForReverseProxySetup/https%3A%2F%2Flocalhost%3A6001%2Fmanage/"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
		},
		{ // See KEYCLOAK-11276
			URI:                     "/iiif/2/edepot_local:ST%2F00001%2FST00005_00001.jpg/full/1000,/0/default.png",
			ExpectedContentContains: `"uri":"/iiif/2/edepot_local:ST%2F00001%2FST00005_00001.jpg/full/1000,/0/default.png"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
		},
		{ // See KEYCLOAK-13315
			URI:                     "/rabbitmqui/%2F/replicate-to-central",
			ExpectedContentContains: `"uri":"/rabbitmqui/%2F/replicate-to-central"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
		},
		{ // should work
			URI:           "/api/v1/auth",
			HasToken:      true,
			Roles:         []string{"admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{ // should work
			URI:                     "/api/v1/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth",
			ExpectedContentContains: `"uri":"/api/v1/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth"`,
			HasToken:                true,
			Roles:                   []string{"admin"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
		},
		{
			URI:          "/api/v1/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth",
			HasToken:     true,
			Roles:        []string{"user"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // should work
			URI:                     "/api/v3/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth",
			ExpectedContentContains: `"uri":"/api/v3/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
		},
	}

	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestStrangeRoutingError(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/api/v1/events/123456789",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"user"},
		},
		{
			URL:     "/api/v1/events/404",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"monitoring"},
		},
		{
			URL:     "/api/v1/audit/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"auditor", "dev"},
		},
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"dev"},
		},
	}
	requests := []fakeRequest{
		{ // should work
			URI:                     "/api/v1/events/123456789",
			HasToken:                true,
			Redirects:               true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: `"uri":"/api/v1/events/123456789"`,
		},
		{ // should break with bad role
			URI:          "/api/v1/events/123456789",
			HasToken:     true,
			Redirects:    true,
			Roles:        []string{"bad_role"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // good
			URI:           "/api/v1/events/404",
			HasToken:      true,
			Redirects:     false,
			Roles:         []string{"monitoring", "test"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{ // this should fail with no roles - hits catch all
			URI:          "/api/v1/event/1000",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // this should fail with bad role - hits catch all
			URI:          "/api/v1/event/1000",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"bad"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // should work with catch-all
			URI:           "/api/v1/event/1000",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{"dev"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}

	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestNoProxyingRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
		},
	}
	requests := []fakeRequest{
		{ // check for escaping
			URI:          "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for escaping
			URI:          "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for escaping
			URI:          "/../%2e",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for escaping
			URI:          "",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

const testAdminURI = "/admin/test"

func TestStrangeAdminRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/admin*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
	}
	requests := []fakeRequest{
		{ // check for escaping
			URI:          "//admin%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for escaping
			URI:          "///admin/../admin//%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for escaping
			URI:          "/admin%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for prefix slashs
			URI:          "/" + testAdminURI,
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for double slashs
			URI:          testAdminURI,
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for double slashs no redirects
			URI:          "/admin//test",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check for dodgy url
			URI:          "//admin/.." + testAdminURI,
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for it works
			URI:           "/" + testAdminURI,
			HasToken:      true,
			Roles:         []string{fakeAdminRole},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{ // check for is doens't work
			URI:          "//admin//test",
			HasToken:     true,
			Roles:        []string{"bad"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/help/../admin/test/21",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestWhiteListedRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{fakeTestRole},
		},
		{
			URL:         "/whitelist*",
			WhiteListed: true,
			Methods:     utils.AllHTTPMethods,
		},
	}
	requests := []fakeRequest{
		{ // check whitelisted is passed
			URI:           "/whitelist",
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check whitelisted is passed
			URI:           "/whitelist/test",
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/test",
			HasToken:     true,
			Roles:        []string{"nothing"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:           "/",
			HasToken:      true,
			ExpectedProxy: true,
			Roles:         []string{fakeTestRole},
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestRequireAnyRoles(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:            "/require_any_role/*",
			Methods:        utils.AllHTTPMethods,
			RequireAnyRole: true,
			Roles:          []string{"admin", "guest"},
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/require_any_role/test",
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:           "/require_any_role/test",
			HasToken:      true,
			Roles:         []string{"guest"},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/require_any_role/test",
			HasToken:     true,
			Roles:        []string{"guest1"},
			ExpectedCode: http.StatusForbidden,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestGroupPermissionsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/with_role_and_group*",
			Methods: utils.AllHTTPMethods,
			Groups:  []string{"admin"},
			Roles:   []string{"admin"},
		},
		{
			URL:     "/with_group*",
			Methods: utils.AllHTTPMethods,
			Groups:  []string{"admin"},
		},
		{
			URL:     "/with_many_groups*",
			Methods: utils.AllHTTPMethods,
			Groups:  []string{"admin", "user", "tester"},
		},
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"user"},
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:          "/with_role_and_group/test",
			HasToken:     true,
			Roles:        []string{"admin"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/with_role_and_group/test",
			HasToken:     true,
			Groups:       []string{"admin"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/with_role_and_group/test",
			HasToken:      true,
			Groups:        []string{"admin"},
			Roles:         []string{"admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/with_group/hello",
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/with_groupdd",
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/with_group/hello",
			HasToken:     true,
			Groups:       []string{"bad"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/with_group/hello",
			HasToken:      true,
			Groups:        []string{"admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/with_group/hello",
			HasToken:      true,
			Groups:        []string{"test", "admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/with_many_groups/test",
			HasToken:     true,
			Groups:       []string{"bad"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/with_many_groups/test",
			HasToken:      true,
			Groups:        []string{"user"},
			Roles:         []string{"test"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/with_many_groups/test",
			HasToken:      true,
			Groups:        []string{"tester", "user"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/with_many_groups/test",
			HasToken:      true,
			Groups:        []string{"bad", "user"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestRolePermissionsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/admin*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
		{
			URL:     "/test*",
			Methods: []string{"GET"},
			Roles:   []string{fakeTestRole},
		},
		{
			URL:     "/test_admin_role*",
			Methods: []string{"GET"},
			Roles:   []string{fakeAdminRole, fakeTestRole},
		},
		{
			URL:     "/section/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
		{
			URL:     "/section/one",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"one"},
		},
		{
			URL:     "/whitelist",
			Methods: []string{"GET"},
			Roles:   []string{},
		},
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{fakeTestRole},
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // check for redirect
			URI:          "/",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check with a token but not test role
			URI:          "/",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with a token and wrong roles
			URI:          "/",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"one", "two"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // token, wrong roles
			URI:          "/test",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"bad_role"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // token, but post method
			URI:           "/test",
			Method:        http.MethodPost,
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check with correct token
			URI:           "/test",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check with correct token on base
			URI:           "/",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check with correct token, not signed
			URI:          "/",
			Redirects:    false,
			HasToken:     true,
			NotSigned:    true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // check with correct token, signed
			URI:          "/admin/page",
			Method:       http.MethodPost,
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with correct token, signed, wrong roles (10)
			URI:          "/admin/page",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with correct token, signed, wrong roles
			URI:           "/admin/page",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole, fakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // strange url
			URI:          "/admin/..//admin/page",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // strange url, token
			URI:          "/admin/../admin",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"hehe"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // strange url, token
			URI:          "/test/../admin",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // strange url, token, role (15)
			URI:           "/test/../admin",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // strange url, token, but good token
			URI:           "/test/../admin",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // strange url, token, wrong roles
			URI:          "/test/../admin",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with a token admin test role
			URI:          "/test_admin_role",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with a token but without both roles
			URI:          "/test_admin_role",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
			Roles:        []string{fakeAdminRole},
		},
		{ // check with a token with both roles (20)
			URI:           "/test_admin_role",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeAdminRole, fakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/section/test1",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/section/test",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole, fakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/section/one",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{fakeTestRole, fakeAdminRole},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/section/one",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{"one"},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestCrossSiteHandler(t *testing.T) {
	cases := []struct {
		Cors    cors.Options
		Request fakeRequest
	}{
		{
			Cors: cors.Options{
				AllowedOrigins: []string{"*"},
			},
			Request: fakeRequest{
				URI: fakeAuthAllURL,
				Headers: map[string]string{
					"Origin": "127.0.0.1",
				},
				ExpectedHeaders: map[string]string{
					"Access-Control-Allow-Origin": "*",
				},
			},
		},
		{
			Cors: cors.Options{
				AllowedOrigins: []string{"*", "https://examples.com"},
			},
			Request: fakeRequest{
				URI: fakeAuthAllURL,
				Headers: map[string]string{
					"Origin": "127.0.0.1",
				},
				ExpectedHeaders: map[string]string{
					"Access-Control-Allow-Origin": "*",
				},
			},
		},
		{
			Cors: cors.Options{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST"},
			},
			Request: fakeRequest{
				URI:    fakeAuthAllURL,
				Method: http.MethodOptions,
				Headers: map[string]string{
					"Origin":                        "127.0.0.1",
					"Access-Control-Request-Method": "GET",
				},
				ExpectedHeaders: map[string]string{
					"Access-Control-Allow-Origin":  "*",
					"Access-Control-Allow-Methods": "GET",
				},
			},
		},
	}

	for _, testCase := range cases {
		cfg := newFakeKeycloakConfig()
		cfg.CorsCredentials = testCase.Cors.AllowCredentials
		cfg.CorsExposedHeaders = testCase.Cors.ExposedHeaders
		cfg.CorsHeaders = testCase.Cors.AllowedHeaders
		cfg.CorsMaxAge = time.Duration(testCase.Cors.MaxAge) * time.Second
		cfg.CorsMethods = testCase.Cors.AllowedMethods
		cfg.CorsOrigins = testCase.Cors.AllowedOrigins

		newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, []fakeRequest{testCase.Request})
	}
}

func TestRefreshToken(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestRefreshTokenEncryption",
			ProxySettings: func(c *Config) {
				c.EnableRefreshTokens = true
				c.EnableEncryptedToken = true
				c.Verbose = true
				c.EnableLogging = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                           fakeAuthAllURL,
					HasLogin:                      true,
					Redirects:                     true,
					OnResponse:                    delay,
					ExpectedProxy:                 true,
					ExpectedCode:                  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieRefreshName: checkRefreshTokenEncryption},
				},
				{
					URI:           fakeAuthAllURL,
					Redirects:     false,
					HasLogin:      false,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
				},
			},
		},
		{
			Name: "TestRefreshTokenExpiration",
			ProxySettings: func(c *Config) {
				c.EnableRefreshTokens = true
				c.EnableEncryptedToken = true
				c.Verbose = true
				c.EnableLogging = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:       fakeAuthAllURL,
					HasLogin:  true,
					Redirects: true,
					OnResponse: func(int, *resty.Request, *resty.Response) {
						<-time.After(time.Duration(int64(3200)) * time.Millisecond)
					},
					ExpectedProxy:                 true,
					ExpectedCode:                  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieRefreshName: checkRefreshTokenEncryption},
				},
				{
					URI:           fakeAuthAllURL,
					Redirects:     false,
					HasLogin:      false,
					ExpectedProxy: false,
					ExpectedCode:  http.StatusUnauthorized,
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
				p := newFakeProxy(c, &fakeAuthConfig{Expiration: 1500 * time.Millisecond})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func delay(no int, req *resty.Request, resp *resty.Response) {
	if no == 0 {
		<-time.After(1000 * time.Millisecond)
	}
}

func checkAccessTokenEncryption(t *testing.T, cfg *Config, value string) bool {
	rawToken, err := utils.DecodeText(value, cfg.EncryptionKey)

	if err != nil {
		return false
	}

	token, err := jwt.ParseSigned(rawToken)

	if err != nil {
		return false
	}

	user, err := extractIdentity(token)

	if err != nil {
		return false
	}

	return assert.Contains(t, user.claims, "aud") && assert.Contains(t, user.claims, "email")
}

func checkRefreshTokenEncryption(t *testing.T, cfg *Config, value string) bool {
	rawToken, err := utils.DecodeText(value, cfg.EncryptionKey)

	if err != nil {
		return false
	}

	_, err = jwt.ParseSigned(rawToken)

	return err == nil
}

func TestAccessTokenEncryption(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	redisServer, err := miniredis.Run()

	if err != nil {
		t.Fatalf("Starting redis failed %s", err)
	}

	defer redisServer.Close()

	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestEnableEncryptedTokenWithRedis",
			ProxySettings: func(conf *Config) {
				conf.EnableRefreshTokens = true
				conf.EnableEncryptedToken = true
				conf.Verbose = true
				conf.EnableLogging = true
				conf.EncryptionKey = testEncryptionKey
				conf.StoreURL = fmt.Sprintf("redis://%s", redisServer.Addr())
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:       fakeAuthAllURL,
					HasLogin:  true,
					Redirects: true,
					OnResponse: func(int, *resty.Request, *resty.Response) {
						<-time.After(time.Duration(int64(2500)) * time.Millisecond)
					},
					ExpectedProxy:                 true,
					ExpectedCode:                  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieAccessName: checkAccessTokenEncryption},
				},
				{
					URI:                      fakeAuthAllURL,
					Redirects:                false,
					ExpectedProxy:            true,
					ExpectedCode:             http.StatusOK,
					ExpectedCookies:          map[string]string{cfg.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieAccessName: checkAccessTokenEncryption},
				},
			},
		},
		{
			Name: "TestEnableEncryptedToken",
			ProxySettings: func(conf *Config) {
				conf.EnableRefreshTokens = true
				conf.EnableEncryptedToken = true
				conf.Verbose = true
				conf.EnableLogging = true
				conf.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:       fakeAuthAllURL,
					HasLogin:  true,
					Redirects: true,
					OnResponse: func(int, *resty.Request, *resty.Response) {
						<-time.After(time.Duration(int64(2500)) * time.Millisecond)
					},
					ExpectedProxy:                 true,
					ExpectedCode:                  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieAccessName: checkAccessTokenEncryption},
				},
				{
					URI:                      fakeAuthAllURL,
					Redirects:                false,
					ExpectedProxy:            true,
					ExpectedCode:             http.StatusOK,
					ExpectedCookies:          map[string]string{cfg.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieAccessName: checkAccessTokenEncryption},
				},
			},
		},
		{
			Name: "ForceEncryptedCookie",
			ProxySettings: func(conf *Config) {
				conf.EnableRefreshTokens = true
				conf.EnableEncryptedToken = false
				conf.ForceEncryptedCookie = true
				conf.Verbose = true
				conf.EnableLogging = true
				conf.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:       fakeAuthAllURL,
					HasLogin:  true,
					Redirects: true,
					OnResponse: func(int, *resty.Request, *resty.Response) {
						<-time.After(time.Duration(int64(2500)) * time.Millisecond)
					},
					ExpectedProxy:                 true,
					ExpectedCode:                  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieAccessName: checkAccessTokenEncryption},
				},
				{
					URI:                      fakeAuthAllURL,
					Redirects:                false,
					ExpectedProxy:            true,
					ExpectedCode:             http.StatusOK,
					ExpectedCookies:          map[string]string{cfg.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieAccessName: checkAccessTokenEncryption},
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
				p := newFakeProxy(c, &fakeAuthConfig{Expiration: 2000 * time.Millisecond})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestCustomHeadersHandler(t *testing.T) {
	requests := []struct {
		Match   []string
		Request fakeRequest
	}{
		{
			Match: []string{"subject", "userid", "email", "username"},
			Request: fakeRequest{
				URI:      fakeAuthAllURL,
				HasToken: true,
				TokenClaims: map[string]interface{}{
					"sub":                "test-subject",
					"username":           "rohith",
					"preferred_username": "rohith",
					"email":              "gambol99@gmail.com",
				},
				ExpectedProxyHeaders: map[string]string{
					"X-Auth-Subject":  "test-subject",
					"X-Auth-Userid":   "rohith",
					"X-Auth-Email":    "gambol99@gmail.com",
					"X-Auth-Username": "rohith",
				},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Match: []string{"given_name", "family_name", "preferred_username|Custom-Header"},
			Request: fakeRequest{
				URI:      fakeAuthAllURL,
				HasToken: true,
				TokenClaims: map[string]interface{}{
					"email":              "gambol99@gmail.com",
					"name":               "Rohith Jayawardene",
					"family_name":        "Jayawardene",
					"preferred_username": "rjayawardene",
					"given_name":         "Rohith",
				},
				ExpectedProxyHeaders: map[string]string{
					"X-Auth-Given-Name":  "Rohith",
					"X-Auth-Family-Name": "Jayawardene",
					"Custom-Header":      "rjayawardene",
				},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
	}
	for _, c := range requests {
		cfg := newFakeKeycloakConfig()
		cfg.AddClaims = c.Match
		newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, []fakeRequest{c.Request})
	}
}

func TestAdmissionHandlerRoles(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.NoRedirects = true
	cfg.Resources = []*Resource{
		{
			URL:     "/admin",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"admin"},
		},
		{
			URL:     "/test",
			Methods: []string{"GET"},
			Roles:   []string{"test"},
		},
		{
			URL:     "/either",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"admin", "test"},
		},
		{
			URL:     "/",
			Methods: utils.AllHTTPMethods,
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/admin",
			Roles:        []string{},
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/admin",
			Roles:         []string{"admin"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/test",
			Roles:         []string{"test"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/either",
			Roles:         []string{"test", "admin"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/either",
			Roles:        []string{"no_roles"},
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/",
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

// check to see if custom headers are hitting the upstream
func TestCustomHeaders(t *testing.T) {
	requests := []struct {
		Headers map[string]string
		Request fakeRequest
	}{
		{
			Headers: map[string]string{
				"TestHeaderOne": "one",
			},
			Request: fakeRequest{
				URI:           "/gambol99.htm",
				ExpectedProxy: true,
				ExpectedProxyHeaders: map[string]string{
					"TestHeaderOne": "one",
				},
			},
		},
		{
			Headers: map[string]string{
				"TestHeader": "test",
			},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				ExpectedProxy: true,
				ExpectedProxyHeaders: map[string]string{
					"TestHeader": "test",
				},
			},
		},
		{
			Headers: map[string]string{
				"TestHeaderOne": "one",
				"TestHeaderTwo": "two",
			},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				ExpectedProxy: true,
				ExpectedProxyHeaders: map[string]string{
					"TestHeaderOne": "one",
					"TestHeaderTwo": "two",
				},
			},
		},
	}
	for _, c := range requests {
		cfg := newFakeKeycloakConfig()
		cfg.Resources = []*Resource{{URL: "/admin*", Methods: utils.AllHTTPMethods}}
		cfg.Headers = c.Headers
		newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, []fakeRequest{c.Request})
	}
}

func TestRolesAdmissionHandlerClaims(t *testing.T) {
	requests := []struct {
		Matches map[string]string
		Request fakeRequest
	}{
		// jose.StringClaim test
		{
			Matches: map[string]string{"item": "test"},
			Request: fakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^tes$"},
			Request: fakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^tes$"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   map[string]interface{}{"item": "tes"},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": "not_match"},
			Request: fakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				TokenClaims:  map[string]interface{}{"item": "test"},
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^test", "found": "something"},
			Request: fakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				TokenClaims:  map[string]interface{}{"item": "test"},
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^test", "found": "something"},
			Request: fakeRequest{
				URI:      testAdminURI,
				HasToken: true,
				TokenClaims: map[string]interface{}{
					"item":  "tester",
					"found": "something",
				},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": ".*"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   map[string]interface{}{"item": "test"},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": "^t.*$"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   map[string]interface{}{"item": "test"},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		// jose.StringsClaim test
		{
			Matches: map[string]string{"item1": "^t.*t"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   map[string]interface{}{"item1": []string{"nonMatchingClaim", "test", "anotherNonMatching"}},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item1": "^t.*t"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   map[string]interface{}{"item1": []string{"1test", "2test", "3test"}},
				ExpectedProxy: false,
				ExpectedCode:  http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^t.*t"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   map[string]interface{}{"item1": []string{}},
				ExpectedProxy: false,
				ExpectedCode:  http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{
				"item1": "^t.*t",
				"item2": "^another",
			},
			Request: fakeRequest{
				URI:      testAdminURI,
				HasToken: true,
				TokenClaims: map[string]interface{}{
					"item1": []string{"randomItem", "test"},
					"item2": []string{"randomItem", "anotherItem"},
					"item3": []string{"randomItem2", "anotherItem3"},
				},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
	}
	for _, c := range requests {
		cfg := newFakeKeycloakConfig()
		cfg.Resources = []*Resource{{URL: "/admin*", Methods: utils.AllHTTPMethods}}
		cfg.MatchClaims = c.Matches
		newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, []fakeRequest{c.Request})
	}
}

func TestGzipCompression(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	server := httptest.NewServer(&fakeUpstreamService{})

	requests := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestCompressionWithCustomURI",
			ProxySettings: func(c *Config) {
				c.EnableCompression = true
				c.EnableLogging = false
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/gambol99.htm",
					ExpectedProxy: true,
					Headers: map[string]string{
						"Accept-Encoding": "gzip, deflate, br",
					},
					ExpectedHeaders: map[string]string{
						"Content-Encoding": "gzip",
					},
				},
			},
		},
		{
			Name: "TestCompressionWithAdminURI",
			ProxySettings: func(c *Config) {
				c.EnableCompression = true
				c.EnableLogging = false
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           testAdminURI,
					ExpectedProxy: false,
					Headers: map[string]string{
						"Accept-Encoding": "gzip, deflate, br",
					},
					ExpectedNoProxyHeaders: []string{"Content-Encoding"},
				},
			},
		},
		{
			Name: "TestCompressionWithLogging",
			ProxySettings: func(c *Config) {
				c.EnableCompression = true
				c.EnableLogging = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     server.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "/test",
					Headers: map[string]string{
						"Accept-Encoding": "gzip, deflate, br",
					},
					ExpectedHeaders: map[string]string{
						"Content-Encoding": "gzip",
					},
				},
			},
		},
		{
			Name: "TestWithoutCompressionCustomURI",
			ProxySettings: func(c *Config) {
				c.EnableCompression = false
				c.EnableLogging = false
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/gambol99.htm",
					ExpectedProxy: true,
					Headers: map[string]string{
						"Accept-Encoding": "gzip, deflate, br",
					},
					ExpectedNoProxyHeaders: []string{"Content-Encoding"},
				},
			},
		},
		{
			Name: "TestWithoutCompressionWithAdminURI",
			ProxySettings: func(c *Config) {
				c.EnableCompression = false
				c.EnableLogging = false
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           testAdminURI,
					ExpectedProxy: false,
					Headers: map[string]string{
						"Accept-Encoding": "gzip, deflate, br",
					},
					ExpectedNoProxyHeaders: []string{"Content-Encoding"},
				},
			},
		},
	}

	for _, testCase := range requests {
		testCase := testCase
		cfg := *cfg
		cfg.Resources = []*Resource{{URL: "/admin*", Methods: utils.AllHTTPMethods}}

		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(&cfg)
				p := newFakeProxy(&cfg, &fakeAuthConfig{})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestEnableUma(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	requests := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestUmaNoToken",
			ProxySettings: func(conf *Config) {
				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = validUsername
				conf.ClientSecret = validPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/test",
					ExpectedProxy: false,
					ExpectedCode:  http.StatusUnauthorized,
					ExpectedContent: func(body string, testNum int) {
						assert.Equal(t, "", body)
					},
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"WWW-Authenticate": func(t *testing.T, c *Config, value string) {
							assert.Contains(t, "ticket", value)
						},
					},
				},
			},
		},
		{
			Name: "TestUmaTokenWithoutAuthz",
			ProxySettings: func(conf *Config) {
				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = validUsername
				conf.ClientSecret = validPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                "/test",
					ExpectedProxy:      false,
					HasToken:           true,
					ExpectedCode:       http.StatusUnauthorized,
					TokenAuthorization: &authorization.Permissions{},
					ExpectedContent: func(body string, testNum int) {
						assert.Equal(t, "", body)
					},
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"WWW-Authenticate": func(t *testing.T, c *Config, value string) {
							assert.Contains(t, "ticket", value)
						},
					},
				},
			},
		},
		{
			Name: "TestUmaTokenWithoutResourceId",
			ProxySettings: func(conf *Config) {
				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = validUsername
				conf.ClientSecret = validPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/test",
					ExpectedProxy: false,
					HasToken:      true,
					ExpectedCode:  http.StatusUnauthorized,
					TokenAuthorization: &authorization.Permissions{
						Permissions: []authorization.Permission{
							{
								Scopes:       []string{"test"},
								ResourceID:   "",
								ResourceName: "some",
							},
						},
					},
					ExpectedContent: func(body string, testNum int) {
						assert.Equal(t, "", body)
					},
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"WWW-Authenticate": func(t *testing.T, c *Config, value string) {
							assert.Contains(t, "ticket", value)
						},
					},
				},
			},
		},
		{
			Name: "TestUmaTokenWithoutScope",
			ProxySettings: func(conf *Config) {
				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = validUsername
				conf.ClientSecret = validPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/test",
					ExpectedProxy: false,
					HasToken:      true,
					ExpectedCode:  http.StatusUnauthorized,
					TokenAuthorization: &authorization.Permissions{
						Permissions: []authorization.Permission{
							{
								Scopes:       []string{},
								ResourceID:   "6ef1b62e-0fd4-47f2-81fc-eead97a01c22",
								ResourceName: "some",
							},
						},
					},
					ExpectedContent: func(body string, testNum int) {
						assert.Equal(t, "", body)
					},
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"WWW-Authenticate": func(t *testing.T, c *Config, value string) {
							assert.Contains(t, "ticket", value)
						},
					},
				},
			},
		},
		{
			Name: "TestUmaOK",
			ProxySettings: func(conf *Config) {
				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = validUsername
				conf.ClientSecret = validPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/test",
					ExpectedProxy: true,
					HasToken:      true,
					ExpectedCode:  http.StatusOK,
					TokenAuthorization: &authorization.Permissions{
						Permissions: []authorization.Permission{
							{
								Scopes:       []string{"test"},
								ResourceID:   "6ef1b62e-0fd4-47f2-81fc-eead97a01c22",
								ResourceName: "some",
							},
						},
					},
					ExpectedContent: func(body string, testNum int) {
						assert.Contains(t, body, "test")
						assert.Contains(t, body, "method")
					},
				},
			},
		},
	}

	for _, testCase := range requests {
		testCase := testCase
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

//nolint:funlen,cyclop
func TestEnableUmaWithCache(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	requests := []struct {
		Name                 string
		PreRequestSettings   func(p *fakeProxy, reqs []fakeRequest) ([]fakeRequest, error)
		ProxySettings        func(c *Config)
		ExecutionSettings    []fakeRequest
		ExpectedCacheEntries int
		ExpectedCacheValues  authorization.AuthzDecision
	}{
		{
			Name: "TestUmaTokenWithoutAuthzWithDifferentTokens",
			ProxySettings: func(conf *Config) {
				redisServer, err := miniredis.Run()

				if err != nil {
					t.Fatalf("Starting redis failed %s", err)
				}

				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = validUsername
				conf.ClientSecret = validPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
				conf.StoreURL = fmt.Sprintf("redis://%s", redisServer.Addr())
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/test",
					ExpectedProxy: false,
					HasToken:      true,
					ExpectedCode:  http.StatusUnauthorized,
					TokenAuthorization: &authorization.Permissions{
						Permissions: []authorization.Permission{
							{
								Scopes:       []string{},
								ResourceID:   "43322-0fd4-47f2-81fc-eead97a01c22",
								ResourceName: "some",
							},
						},
					},
					ExpectedContent: func(body string, testNum int) {
						assert.Equal(t, "", body)
					},
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"WWW-Authenticate": func(t *testing.T, c *Config, value string) {
							assert.Contains(t, "ticket", value)
						},
					},
				},
				{
					URI:           "/test",
					ExpectedProxy: false,
					HasToken:      true,
					ExpectedCode:  http.StatusUnauthorized,
					TokenAuthorization: &authorization.Permissions{
						Permissions: []authorization.Permission{
							{
								Scopes:       []string{},
								ResourceID:   "5422-0fd4-47f2-81fc-eead97a01c22",
								ResourceName: "someother",
							},
						},
					},
					ExpectedContent: func(body string, testNum int) {
						assert.Equal(t, "", body)
					},
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"WWW-Authenticate": func(t *testing.T, c *Config, value string) {
							assert.Contains(t, "ticket", value)
						},
					},
				},
			},
			ExpectedCacheEntries: 2,
			ExpectedCacheValues:  authorization.DeniedAuthz,
		},
		{
			Name: "TestUmaOKWithDifferentTokens",
			ProxySettings: func(conf *Config) {
				redisServer, err := miniredis.Run()

				if err != nil {
					t.Fatalf("Starting redis failed %s", err)
				}

				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = validUsername
				conf.ClientSecret = validPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
				conf.StoreURL = fmt.Sprintf("redis://%s", redisServer.Addr())
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/test",
					ExpectedProxy: true,
					HasToken:      true,
					ExpectedCode:  http.StatusOK,
					TokenAuthorization: &authorization.Permissions{
						Permissions: []authorization.Permission{
							{
								Scopes:       []string{"test"},
								ResourceID:   "6ef1b62e-0fd4-47f2-81fc-eead97a01c22",
								ResourceName: "some",
							},
						},
					},
					ExpectedContent: func(body string, testNum int) {
						assert.Contains(t, body, "test")
						assert.Contains(t, body, "method")
					},
				},
				{
					URI:           "/test",
					ExpectedProxy: true,
					HasToken:      true,
					ExpectedCode:  http.StatusOK,
					TokenAuthorization: &authorization.Permissions{
						Permissions: []authorization.Permission{
							{
								Scopes:       []string{"test"},
								ResourceID:   "6ef1b62e-0fd4-47f2-81fc-eead97a01c22",
								ResourceName: "other",
							},
						},
					},
					ExpectedContent: func(body string, testNum int) {
						assert.Contains(t, body, "test")
						assert.Contains(t, body, "method")
					},
				},
			},
			ExpectedCacheEntries: 2,
			ExpectedCacheValues:  authorization.AllowedAuthz,
		},
		{
			Name: "TestUmaOKWithSameTokens",
			PreRequestSettings: func(p *fakeProxy, reqs []fakeRequest) ([]fakeRequest, error) {
				token := newTestToken(p.idp.getLocation())
				token.claims.Authorization = authorization.Permissions{
					Permissions: []authorization.Permission{
						{
							Scopes:       []string{"test"},
							ResourceID:   "6ef1b62e-0fd4-47f2-81fc-eead97a01c22",
							ResourceName: "some",
						},
					},
				}

				raw, err := token.getToken()

				if err != nil {
					return nil, err
				}

				for i := range reqs {
					reqs[i].RawToken = raw
				}

				return reqs, nil
			},
			ProxySettings: func(conf *Config) {
				redisServer, err := miniredis.Run()

				if err != nil {
					t.Fatalf("Starting redis failed %s", err)
				}

				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = validUsername
				conf.ClientSecret = validPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
				conf.StoreURL = fmt.Sprintf("redis://%s", redisServer.Addr())
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/test",
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedContent: func(body string, testNum int) {
						assert.Contains(t, body, "test")
						assert.Contains(t, body, "method")
					},
				},
				{
					URI:           "/test",
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedContent: func(body string, testNum int) {
						assert.Contains(t, body, "test")
						assert.Contains(t, body, "method")
					},
				},
			},
			ExpectedCacheEntries: 1,
			ExpectedCacheValues:  authorization.AllowedAuthz,
		},
		{
			Name: "TestUmaTokenWithoutAuthzWithSameTokens",
			PreRequestSettings: func(p *fakeProxy, reqs []fakeRequest) ([]fakeRequest, error) {
				token := newTestToken(p.idp.getLocation())

				raw, err := token.getToken()

				if err != nil {
					return nil, err
				}

				for i := range reqs {
					reqs[i].RawToken = raw
				}

				return reqs, nil
			},
			ProxySettings: func(conf *Config) {
				redisServer, err := miniredis.Run()

				if err != nil {
					t.Fatalf("Starting redis failed %s", err)
				}

				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = validUsername
				conf.ClientSecret = validPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
				conf.StoreURL = fmt.Sprintf("redis://%s", redisServer.Addr())
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                "/test",
					ExpectedProxy:      false,
					ExpectedCode:       http.StatusUnauthorized,
					TokenAuthorization: &authorization.Permissions{},
					ExpectedContent: func(body string, testNum int) {
						assert.Equal(t, "", body)
					},
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"WWW-Authenticate": func(t *testing.T, c *Config, value string) {
							assert.Contains(t, "ticket", value)
						},
					},
				},
				{
					URI:                "/test",
					ExpectedProxy:      false,
					ExpectedCode:       http.StatusUnauthorized,
					TokenAuthorization: &authorization.Permissions{},
					ExpectedContent: func(body string, testNum int) {
						assert.Equal(t, "", body)
					},
					ExpectedProxyHeadersValidator: map[string]func(*testing.T, *Config, string){
						"WWW-Authenticate": func(t *testing.T, c *Config, value string) {
							assert.Contains(t, "ticket", value)
						},
					},
				},
			},
			ExpectedCacheEntries: 1,
			ExpectedCacheValues:  authorization.DeniedAuthz,
		},
		{
			Name: "TestUmaOneOKOneWithoutPermissionToken",
			PreRequestSettings: func(p *fakeProxy, reqs []fakeRequest) ([]fakeRequest, error) {
				token := newTestToken(p.idp.getLocation())
				token.claims.Authorization = authorization.Permissions{
					Permissions: []authorization.Permission{
						{
							Scopes:       []string{"test"},
							ResourceID:   "6ef1b62e-0fd4-47f2-81fc-eead97a01c22",
							ResourceName: "some",
						},
					},
				}

				raw, err := token.getToken()

				if err != nil {
					return nil, err
				}

				for i := range reqs {
					reqs[i].RawToken = raw
				}

				return reqs, nil
			},
			ProxySettings: func(conf *Config) {
				redisServer, err := miniredis.Run()

				if err != nil {
					t.Fatalf("Starting redis failed %s", err)
				}

				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = validUsername
				conf.ClientSecret = validPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
				conf.StoreURL = fmt.Sprintf("redis://%s", redisServer.Addr())
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/test",
					ExpectedProxy: false,
					HasToken:      true,
					ExpectedCode:  http.StatusUnauthorized,
					ExpectedContent: func(body string, testNum int) {
						assert.Equal(t, "", body)
					},
				},
				{
					URI:           "/test",
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedContent: func(body string, testNum int) {
						assert.Contains(t, body, "test")
						assert.Contains(t, body, "method")
					},
				},
			},
			ExpectedCacheEntries: 2,
		},
	}

	for _, testCase := range requests {
		testCase := testCase
		c := *cfg
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(&c)
				fProxy := newFakeProxy(&c, &fakeAuthConfig{})
				exSettings := testCase.ExecutionSettings
				var err error

				if testCase.PreRequestSettings != nil {
					exSettings, err = testCase.PreRequestSettings(fProxy, exSettings)
					if err != nil {
						t.Fatalf("problem setting up prerequest settings %s", err)
					}
				}

				fProxy.RunTests(t, exSettings)

				redisStoreInstance, assertOk := fProxy.proxy.store.(storage.RedisStore)

				if !assertOk {
					t.Fatalf("assertion failed")
				}

				result := redisStoreInstance.Client.Keys("*")

				if len(result.Val()) != testCase.ExpectedCacheEntries {
					t.Fatalf(
						"expected number of entries %d, got %d",
						testCase.ExpectedCacheEntries,
						len(result.Val()),
					)
				}

				if testCase.ExpectedCacheValues != authorization.UndefinedAuthz {
					for _, val := range result.Val() {
						result := redisStoreInstance.Client.Get(val)
						if result.Val() != testCase.ExpectedCacheValues.String() {
							t.Fatalf(
								"expecting cached authz %s, got %s",
								testCase.ExpectedCacheValues.String(),
								result.Val(),
							)
						}
					}
				}
			},
		)
	}
}
