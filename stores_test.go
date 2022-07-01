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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/stretchr/testify/assert"
)

func TestCreateStorageRedis(t *testing.T) {
	store, err := createStorage("redis://127.0.0.1")
	assert.NotNil(t, store)
	assert.NoError(t, err)
}

func TestCreateStorageFail(t *testing.T) {
	store, err := createStorage("not_there:///tmp/bolt")
	assert.Nil(t, store)
	assert.Error(t, err)
}

func TestStoreAuthz(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	token := newTestToken("http://test")
	jwt, err := token.getToken()

	if err != nil {
		t.Fatal("Testing token generation failed")
	}

	redisServer, err := miniredis.Run()

	if err != nil {
		t.Fatalf("Starting redis failed %s", err)
	}

	defer redisServer.Close()

	tests := []struct {
		Name            string
		ProxySettings   func(c *Config)
		ExpectedFailure bool
	}{
		{
			Name: "TestEntryInRedis",
			ProxySettings: func(c *Config) {
				c.StoreURL = fmt.Sprintf("redis://%s", redisServer.Addr())
			},
		},
		{
			Name: "TestFailedRedis",
			ProxySettings: func(c *Config) {
				c.StoreURL = fmt.Sprintf("redis://%s", "failed:65000")
			},
			ExpectedFailure: true,
		},
	}

	for _, testCase := range tests {
		testCase := testCase
		c := *cfg
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(&c)
				p := newFakeProxy(&c, &fakeAuthConfig{})

				url, err := url.Parse("http://test.com/test")

				if err != nil {
					t.Fatal("Problem parsing url")
				}

				err = p.proxy.StoreAuthz(jwt, url, authorization.AllowedAuthz, 1*time.Second)

				if err != nil && !testCase.ExpectedFailure {
					t.Fatalf("error storing authz %v", err)
				}

				if !testCase.ExpectedFailure {
					url.Path += "/append"
					err = p.proxy.StoreAuthz(jwt, url, authorization.AllowedAuthz, 1*time.Second)

					if err != nil {
						t.Fatalf("error storing authz %v", err)
					}

					keys := redisServer.Keys()

					if len(keys) != 2 {
						t.Fatalf("expected two keys, got %d", len(keys))
					}

					decision, err := redisServer.Get(keys[0])

					if err != nil {
						t.Fatalf("problem getting value from redis")
					}

					if decision != authorization.AllowedAuthz.String() {
						t.Fatalf("bad decision stored, expected allowed, got %v", decision)
					}
				}
			},
		)
	}
}

func TestGetAuthz(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	token := newTestToken("http://test")
	jwt, err := token.getToken()

	if err != nil {
		t.Fatal("Testing token generation failed")
	}

	tests := []struct {
		Name            string
		ProxySettings   func(c *Config)
		JWT             string
		ExpectedFailure bool
	}{
		{
			Name: "TestEntryInStore",
			ProxySettings: func(c *Config) {
				redisServer, err := miniredis.Run()

				if err != nil {
					t.Fatalf("Starting redis failed %s", err)
				}

				c.StoreURL = fmt.Sprintf("redis://%s", redisServer.Addr())
			},
			JWT: jwt,
		},
		{
			Name: "TestZeroLengthToken",
			ProxySettings: func(c *Config) {
				redisServer, err := miniredis.Run()

				if err != nil {
					t.Fatalf("Starting redis failed %s", err)
				}

				c.StoreURL = fmt.Sprintf("redis://%s", redisServer.Addr())
			},
			JWT:             "",
			ExpectedFailure: true,
		},
		{
			Name: "TestEmptyResponse",
			ProxySettings: func(c *Config) {
				redisServer, err := miniredis.Run()

				if err != nil {
					t.Fatalf("Starting redis failed %s", err)
				}

				c.StoreURL = fmt.Sprintf("redis://%s", redisServer.Addr())
			},
			JWT:             jwt,
			ExpectedFailure: true,
		},
		{
			Name: "TestFailedStore",
			ProxySettings: func(c *Config) {
				_, err := miniredis.Run()

				if err != nil {
					t.Fatalf("Starting redis failed %s", err)
				}

				c.StoreURL = fmt.Sprintf("redis://%s", "failed:65000")
			},
			JWT:             jwt,
			ExpectedFailure: true,
		},
	}

	for _, testCase := range tests {
		testCase := testCase
		c := *cfg
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(&c)
				p := newFakeProxy(&c, &fakeAuthConfig{})

				url, err := url.Parse("http://test.com/test")

				if err != nil {
					t.Fatal("Problem parsing url")
				}

				if !testCase.ExpectedFailure {
					err = p.proxy.StoreAuthz(testCase.JWT, url, authorization.AllowedAuthz, 1*time.Second)

					if err != nil {
						t.Fatalf("error storing authz %s", err)
					}
				}

				dec, err := p.proxy.GetAuthz(testCase.JWT, url)

				if err != nil {
					if !testCase.ExpectedFailure {
						t.Fatalf("error getting authz %s", err)
					}

					if dec != authorization.DeniedAuthz {
						t.Fatalf("expected undefined authz decision, got %s", dec)
					}

					if testCase.JWT == "" && err != ErrZeroLengthToken {
						t.Fatalf("expected error %s, got %s", ErrZeroLengthToken, err)
					}

					if testCase.JWT != "" && err != apperrors.ErrNoAuthzFound && !strings.Contains(c.StoreURL, "failed") {
						t.Fatalf("expected error %s, got %s", apperrors.ErrNoAuthzFound, err)
					}
				}

				if !testCase.ExpectedFailure {
					if dec != authorization.AllowedAuthz {
						t.Fatalf("bad decision stored, expected allowed, got %s", dec)
					}
				}
			},
		)
	}
}
