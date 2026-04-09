//go:build !e2e

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
	"testing"

	"github.com/gogatekeeper/gatekeeper/pkg/keycloak/config"
)

func TestRedirectToAuthorization(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	requests := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestWithoutRedirects",
			ProxySettings: func(c *config.Config) {
				c.NoRedirects = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:          FakeAdminURL,
					ExpectedCode: http.StatusUnauthorized,
					Redirects:    false,
				},
			},
		},
		{
			Name: "TestWithRedirects",
			ProxySettings: func(c *config.Config) {
				c.NoRedirects = false
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:              FakeAdminURL,
					Redirects:        true,
					ExpectedLocation: "/oauth/authorize?state",
					ExpectedCode:     http.StatusSeeOther,
				},
			},
		},
		{
			Name: "TestWithXForwardedHeaders",
			ProxySettings: func(c *config.Config) {
				c.NoRedirects = false
				c.EnableXForwardedHeaders = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:       FakeAdminURL,
					Redirects: true,
					Headers: map[string]string{
						"X-Forwarded-Host":  "testhost",
						"X-Forwarded-Proto": "https",
					},
					ExpectedLocation: "https://testhost/oauth/authorize?state",
					ExpectedCode:     http.StatusSeeOther,
				},
			},
		},
	}

	for _, testCase := range requests {
		cfg := *cfg

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
