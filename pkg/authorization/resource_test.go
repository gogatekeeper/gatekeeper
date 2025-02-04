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

package authorization_test

import (
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeResourceBad(t *testing.T) {
	testCases := []struct {
		Option string
	}{
		{Option: "unknown=bad"},
		{Option: "uri=/|unknown=bad"},
		{Option: "uri"},
		{Option: "uri=hello"},
		{Option: "uri=/|white-listed=ERROR"},
		{Option: "uri=/|require-any-role=BAD"},
	}
	for i, testCase := range testCases {
		if _, err := authorization.NewResource().Parse(testCase.Option); err == nil {
			t.Errorf("case %d should have errored", i)
		}
	}
}

func TestResourceParseOk(t *testing.T) {
	testCases := []struct {
		Option   string
		Resource *authorization.Resource
		Ok       bool
	}{
		{
			Option: "uri=/admin",
			Resource: &authorization.Resource{
				URL:     "/admin",
				Methods: utils.AllHTTPMethods,
			},
			Ok: true,
		},
		{
			Option: "uri=/",
			Resource: &authorization.Resource{
				URL:     "/",
				Methods: utils.AllHTTPMethods,
			},
			Ok: true,
		},
		{
			Option: "uri=/admin/sso|roles=test,test1",
			Resource: &authorization.Resource{
				URL:     "/admin/sso",
				Roles:   []string{"test", "test1"},
				Methods: utils.AllHTTPMethods,
			},
			Ok: true,
		},
		{
			Option: "uri=/admin/sso|roles=test,test1|headers=x-test:val",
			Resource: &authorization.Resource{
				URL:     "/admin/sso",
				Roles:   []string{"test", "test1"},
				Headers: []string{"x-test:val"},
				Methods: utils.AllHTTPMethods,
			},
			Ok: true,
		},
		{
			Option: "uri=/admin/sso|roles=test,test1|headers=x-test:val,x-test1val",
			Resource: &authorization.Resource{
				URL:     "/admin/sso",
				Roles:   []string{"test", "test1"},
				Headers: []string{"x-test:val", "x-test1:val"},
				Methods: utils.AllHTTPMethods,
			},
			Ok: false,
		},
		{
			Option: "uri=/admin/sso|roles=test,test1|methods=GET,POST",
			Resource: &authorization.Resource{
				URL:     "/admin/sso",
				Roles:   []string{"test", "test1"},
				Methods: []string{"GET", "POST"},
			},
			Ok: true,
		},
		{
			Option: "uri=/allow_me|white-listed=true",
			Resource: &authorization.Resource{
				URL:         "/allow_me",
				WhiteListed: true,
				Methods:     utils.AllHTTPMethods,
			},
			Ok: true,
		},
		{
			Option: "uri=/*|methods=any",
			Resource: &authorization.Resource{
				URL:     "/*",
				Methods: utils.AllHTTPMethods,
			},
			Ok: true,
		},
		{
			Option: "uri=/*|methods=any",
			Resource: &authorization.Resource{
				URL:     "/*",
				Methods: utils.AllHTTPMethods,
			},
			Ok: true,
		},
		{
			Option: "uri=/*|groups=admin,test",
			Resource: &authorization.Resource{
				URL:     "/*",
				Methods: utils.AllHTTPMethods,
				Groups:  []string{"admin", "test"},
			},
			Ok: true,
		},
		{
			Option: "uri=/*|groups=admin",
			Resource: &authorization.Resource{
				URL:     "/*",
				Methods: utils.AllHTTPMethods,
				Groups:  []string{"admin"},
			},
			Ok: true,
		},
		{
			Option: "uri=/*|require-any-role=true",
			Resource: &authorization.Resource{
				URL:            "/*",
				Methods:        utils.AllHTTPMethods,
				RequireAnyRole: true,
			},
			Ok: true,
		},
	}
	for i, testCase := range testCases {
		r, err := authorization.NewResource().Parse(testCase.Option)

		if testCase.Ok {
			require.NoError(t, err, "case %d should not have errored with: %s", i, err)
			assert.Equal(t, r, testCase.Resource, "case %d, expected: %#v, got: %#v", i, testCase.Resource, r)
		} else {
			require.Error(t, err)
		}
	}
}

func TestIsValid(t *testing.T) {
	testCases := []struct {
		Resource          *authorization.Resource
		CustomHTTPMethods []string
		Ok                bool
	}{
		{
			Resource: &authorization.Resource{URL: "/test"},
			Ok:       true,
		},
		{
			Resource: &authorization.Resource{URL: "/test", Methods: []string{"GET"}},
			Ok:       true,
		},
		{
			Resource: &authorization.Resource{URL: "/", Methods: utils.AllHTTPMethods},
			Ok:       true,
		},
		{
			Resource: &authorization.Resource{URL: "/admin/", Methods: utils.AllHTTPMethods},
		},
		{
			Resource: &authorization.Resource{},
		},
		{
			Resource: &authorization.Resource{
				URL:     "/test",
				Methods: []string{"NO_SUCH_METHOD"},
			},
		},
		{
			Resource: &authorization.Resource{
				URL:     "/test",
				Methods: []string{"PROPFIND"},
			},
			CustomHTTPMethods: []string{"PROPFIND"},
			Ok:                true,
		},
	}

	for idx, testCase := range testCases {
		for _, customHTTPMethod := range testCase.CustomHTTPMethods {
			chi.RegisterMethod(customHTTPMethod)
			utils.AllHTTPMethods = append(utils.AllHTTPMethods, customHTTPMethod)
		}

		err := testCase.Resource.Valid()

		if (err != nil && testCase.Ok) || (err == nil && !testCase.Ok) {
			t.Errorf("case %d expected test result: %t, error was: %s", idx, testCase.Ok, err)
		}
	}
}

var expectedRoles = []string{"1", "2", "3"}

const rolesList = "1,2,3"

func TestResourceString(t *testing.T) {
	resource := &authorization.Resource{
		Roles: expectedRoles,
	}
	if s := resource.String(); s == "" {
		t.Error("we should have received a string")
	}
}

func TestGetRoles(t *testing.T) {
	resource := &authorization.Resource{
		Roles: expectedRoles,
	}

	if resource.GetRoles() != rolesList {
		t.Error("the resource roles not as expected")
	}
}
