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

package utils_test

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	uuid "github.com/gofrs/uuid"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/cookie"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestDecodeKeyPairs(t *testing.T) {
	testCases := []struct {
		List     []string
		KeyPairs map[string]string
		Ok       bool
	}{
		{
			List: []string{"a=b", "b=3"},
			KeyPairs: map[string]string{
				"a": "b",
				"b": "3",
			},
			Ok: true,
		},
		{
			List: []string{"a=b==", "b=3"},
			KeyPairs: map[string]string{
				"a": "b==",
				"b": "3",
			},
			Ok: true,
		},
		{
			List: []string{"a=", "b=3"},
			KeyPairs: map[string]string{
				"a": "",
				"b": "3",
			},
			Ok: true,
		},
		{
			List: []string{"a=b", "==b==3=="},
			Ok:   false,
		},
		{
			List: []string{"add", "b=3"},
		},
	}

	for idx, testCase := range testCases {
		keyPair, err := utils.DecodeKeyPairs(testCase.List)
		if err != nil && testCase.Ok {
			t.Errorf("test case %d should not have failed", idx)
			continue
		}
		if !testCase.Ok {
			continue
		}
		if !reflect.DeepEqual(keyPair, testCase.KeyPairs) {
			t.Errorf("test case %d are not equal %v <-> %v", idx, keyPair, testCase.KeyPairs)
		}
	}
}

func TestGetRequestHostURL(t *testing.T) {
	testCases := []struct {
		Expected string
		Hostname string
		Headers  map[string]string
		TLS      *tls.ConnectionState
	}{
		{
			Expected: "http://www.test.com",
			Headers:  map[string]string{constant.HeaderXForwardedHost: "www.test.com"},
		},
		{
			Expected: "http://",
		},
		{
			Expected: "http://www.override.com",
			Headers:  map[string]string{constant.HeaderXForwardedHost: "www.override.com"},
			Hostname: "www.test.com",
		},
		{
			Expected: "https://www.test.com",
			Hostname: "www.test.com",
			TLS:      &tls.ConnectionState{},
		},
		{
			Expected: "https://www.override.com",
			Headers:  map[string]string{constant.HeaderXForwardedHost: "www.override.com"},
			Hostname: "www.test.com",
			TLS:      &tls.ConnectionState{},
		},
		{
			Expected: "https://www.override.com",
			Headers: map[string]string{
				constant.HeaderXForwardedHost:  "www.override.com",
				constant.HeaderXForwardedProto: "https",
			},
			Hostname: "www.override.com",
		},
	}

	for idx := range testCases {
		request := &http.Request{
			Method: http.MethodGet,
			Host:   testCases[idx].Hostname,
			TLS:    testCases[idx].TLS,
		}

		if testCases[idx].Headers != nil {
			request.Header = make(http.Header)
			for key := range testCases[idx].Headers {
				request.Header.Set(key, testCases[idx].Headers[key])
			}
		}

		url := utils.GetRequestHostURL(request)
		assert.Equal(t, testCases[idx].Expected, url, "case %d, expected: %s, got: %s", idx, testCases[idx].Expected, url)
	}
}

func BenchmarkUUID(b *testing.B) {
	for b.Loop() {
		s, err := uuid.NewV1()
		if err != nil {
			b.Errorf("test case should not have failed")
		}
		_ = s.String()
	}
}

func TestDefaultTo(t *testing.T) {
	testCases := []struct {
		Value    string
		Default  string
		Expected string
	}{
		{
			Value:    "",
			Default:  "hello",
			Expected: "hello",
		},
		{
			Value:    "world",
			Default:  "hello",
			Expected: "world",
		},
	}
	for _, testCases := range testCases {
		assert.Equal(t, testCases.Expected, utils.DefaultTo(testCases.Value, testCases.Default))
	}
}

/*
func TestEncryptedText(t *testing.T) {
	s, err := encodeText(string(fakePlainText), string(fakeKey))
	require.NoError(t, err)
	require.NotEmpty(t, s)
	d, err := decodeText(s, string(fakeKey))
	require.NoError(t, err)
	require.NotEmpty(t, d)
	assert.Equal(t, string(fakePlainText), d)
	fmt.Printf("Encoded: '%s'\n", s)
	fmt.Printf("Decoded: '%s'\n", d)
}
*/

func TestFindCookie(t *testing.T) {
	cookies := []*http.Cookie{
		{Name: "cookie_there"},
	}
	assert.NotNil(t, cookie.FindCookie("cookie_there", cookies))
	assert.Nil(t, cookie.FindCookie("not_there", cookies))
}

func TestHasAccessOK(t *testing.T) {
	testCases := []struct {
		Have     []string
		Need     []string
		Required bool
	}{
		{},
		{
			Have: []string{"a", "b"},
		},
		{
			Have:     []string{"a", "b", "c"},
			Need:     []string{"a", "b"},
			Required: true,
		},
		{
			Have: []string{"a", "b", "c"},
			Need: []string{"a", "c"},
		},
		{
			Have: []string{"a", "b", "c"},
			Need: []string{"c"},
		},
		{
			Have: []string{"a", "b", "c"},
			Need: []string{"b"},
		},
		{
			Have: []string{"a", "b", "c"},
			Need: []string{"b"},
		},
		{
			Have: []string{"a", "b"},
			Need: []string{"a"},
		},
		{
			Have:     []string{"a", "b"},
			Need:     []string{"a"},
			Required: true,
		},
		{
			Have:     []string{"b", "a"},
			Need:     []string{"a"},
			Required: true,
		},
	}
	for idx, testCase := range testCases {
		assert.True(
			t,
			utils.HasAccess(testCase.Need, testCase.Have, testCase.Required),
			"case: %d should be true, have: %v, need: %v, require: %t ",
			idx,
			testCase.Have,
			testCase.Need,
			testCase.Required,
		)
	}
}

func TestHasAccessBad(t *testing.T) {
	testCases := []struct {
		Have     []string
		Need     []string
		Required bool
	}{
		{
			Have: []string{"a", "b"},
			Need: []string{"c"},
		},
		{
			Have:     []string{"a", "b"},
			Need:     []string{"c"},
			Required: true,
		},
		{
			Have:     []string{"a", "c"},
			Need:     []string{"a", "b"},
			Required: true,
		},
		{
			Have:     []string{"a", "b", "c"},
			Need:     []string{"b", "j"},
			Required: true,
		},
		{
			Have:     []string{"a", "b", "c"},
			Need:     []string{"a", "d"},
			Required: true,
		},
	}

	for idx, testCase := range testCases {
		assert.False(
			t,
			utils.HasAccess(testCase.Need, testCase.Have, testCase.Required),
			"case: %d should be false, have: %v, need: %v, require: %t ",
			idx,
			testCase.Have,
			testCase.Need,
			testCase.Required,
		)
	}
}

func TestContainedIn(t *testing.T) {
	assert.False(t, utils.ContainedIn("1", []string{"2", "3", "4"}))
	assert.True(t, utils.ContainedIn("1", []string{"1", "2", "3", "4"}))
}

func TestContainsSubString(t *testing.T) {
	assert.False(t, utils.ContainsSubString("bar.com", []string{"foo.bar.com"}))
	assert.True(t, utils.ContainsSubString("www.foo.bar.com", []string{"foo.bar.com"}))
	assert.True(t, utils.ContainsSubString("foo.bar.com", []string{"bar.com"}))
	assert.True(t, utils.ContainsSubString("star.domain.com", []string{"domain.com", "domain1.com"}))
	assert.True(t, utils.ContainsSubString("star.domain1.com", []string{"domain.com", "domain1.com"}))
	assert.True(t, utils.ContainsSubString("test.test.svc.cluster.local", []string{"svc.cluster.local"}))

	assert.False(t, utils.ContainsSubString("star.domain1.com", []string{"domain.com", "sub.domain1.com"}))
	assert.False(t, utils.ContainsSubString("svc.cluster.local", []string{"nginx.pr1.svc.cluster.local"}))
	assert.False(t, utils.ContainsSubString("cluster.local", []string{"nginx.pr1.svc.cluster.local"}))
	assert.False(t, utils.ContainsSubString("pr1", []string{"nginx.pr1.svc.cluster.local"}))
}

func BenchmarkContainsSubString(t *testing.B) {
	for range t.N {
		utils.ContainsSubString("svc.cluster.local", []string{"nginx.pr1.svc.cluster.local"})
	}
}

func TestDialAddress(t *testing.T) {
	assert.Equal(t, "127.0.0.1:80", utils.DialAddress(getFakeURL("http://127.0.0.1")))
	assert.Equal(t, "127.0.0.1:443", utils.DialAddress(getFakeURL("https://127.0.0.1")))
	assert.Equal(t, "127.0.0.1:8080", utils.DialAddress(getFakeURL("http://127.0.0.1:8080")))
}

func TestIsUpgradedConnection(t *testing.T) {
	header := http.Header{}
	header.Add(constant.HeaderUpgrade, "")
	assert.False(t, utils.IsUpgradedConnection(&http.Request{Header: header}))
	header.Set(constant.HeaderUpgrade, "set")
	assert.True(t, utils.IsUpgradedConnection(&http.Request{Header: header}))
}

func TestIdValidHTTPMethod(t *testing.T) {
	testCases := []struct {
		Method string
		Ok     bool
	}{
		{Method: "GET", Ok: true},
		{Method: "GETT"},
		{Method: "CONNECT", Ok: false},
		{Method: "PUT", Ok: true},
		{Method: "PATCH", Ok: true},
	}
	for _, testCase := range testCases {
		assert.Equal(t, testCase.Ok, utils.IsValidHTTPMethod(testCase.Method))
	}
}

func TestFileExists(t *testing.T) {
	if utils.FileExists("no_such_file_exsit_32323232") {
		t.Error("we should have received false")
	}

	tmpfile, err := os.CreateTemp(
		os.TempDir()+"",
		fmt.Sprintf("test_file_%d", os.Getpid()),
	)
	if err != nil {
		t.Fatalf("failed to create the temporary file, %s", err)
	}

	defer os.Remove(tmpfile.Name())

	if !utils.FileExists(tmpfile.Name()) {
		t.Error("we should have received a true")
	}
}

func TestGetWithin(t *testing.T) {
	testCases := []struct {
		Expires  time.Time
		Percent  float64
		Expected time.Duration
	}{
		{
			Expires:  time.Now().Add(time.Duration(1) * time.Hour),
			Percent:  0.10,
			Expected: 359000000000,
		},
		{
			Expires:  time.Now().Add(time.Duration(1) * time.Hour),
			Percent:  0.20,
			Expected: 719000000000,
		},
	}
	for _, testCase := range testCases {
		assert.InDelta(
			t,
			testCase.Expected,
			utils.GetWithin(testCase.Expires, testCase.Percent),
			1000000001,
		)
	}
}

func TestToHeader(t *testing.T) {
	cases := []struct {
		Word     string
		Expected string
	}{
		{
			Word:     "given_name",
			Expected: "Given-Name",
		},
		{
			Word:     "family%name",
			Expected: "Family-Name",
		},
		{
			Word:     "perferredname",
			Expected: "Perferredname",
		},
	}
	for index, testCase := range cases {
		assert.Equal(
			t,
			testCase.Expected,
			utils.ToHeader(testCase.Word),
			"case %d, expected: %s but got: %s",
			index,
			testCase.Expected,
			utils.ToHeader(testCase.Word),
		)
	}
}

func TestCapitalize(t *testing.T) {
	cases := []struct {
		Word     string
		Expected string
	}{
		{
			Word:     "given",
			Expected: "Given",
		},
		{
			Word:     "1iven",
			Expected: "1iven",
		},
		{
			Word:     "Test this",
			Expected: "Test this",
		},
	}
	for index, testCase := range cases {
		assert.Equal(
			t,
			testCase.Expected,
			utils.Capitalize(testCase.Word),
			"case %d, expected: %s but got: %s",
			index,
			testCase.Expected,
			utils.Capitalize(testCase.Word),
		)
	}
}

func TestMergeMaps(t *testing.T) {
	cases := []struct {
		Source   map[string]string
		Dest     map[string]string
		Expected map[string]string
	}{
		{
			Source: map[string]string{
				"a": "b",
				"b": "b",
			},
			Dest: map[string]string{
				"c": "c",
			},
			Expected: map[string]string{
				"a": "b",
				"b": "b",
				"c": "c",
			},
		},
	}
	for index, testCase := range cases {
		merged := utils.MergeMaps(testCase.Dest, testCase.Source)
		if !reflect.DeepEqual(testCase.Expected, merged) {
			t.Errorf(
				"case %d, expected: %v but got: %v",
				index,
				testCase.Expected,
				merged,
			)
		}
	}
}

func getFakeURL(location string) *url.URL {
	u, _ := url.Parse(location)
	return u
}
