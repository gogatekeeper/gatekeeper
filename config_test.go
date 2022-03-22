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
	"os"
	"testing"
)

func TestNewDefaultConfig(t *testing.T) {
	if config := newDefaultConfig(); config == nil {
		t.Error("we should have received a config")
	}
}

func TestIsConfig(t *testing.T) {
	tests := []struct {
		Config *Config
		Ok     bool
	}{
		{
			Config: &Config{},
		},
		{
			Config: &Config{
				DiscoveryURL: "http://127.0.0.1:8080",
			},
		},
		{
			Config: &Config{
				DiscoveryURL: "http://127.0.0.1:8080",
				ClientID:     "client",
				ClientSecret: "client",
			},
		},
		{
			Config: &Config{
				Listen:         ":8080",
				DiscoveryURL:   "http://127.0.0.1:8080",
				ClientID:       "client",
				ClientSecret:   "client",
				RedirectionURL: "http://120.0.0.1",
			},
		},
		{
			Config: &Config{
				Listen:         ":8080",
				DiscoveryURL:   "http://127.0.0.1:8080",
				ClientID:       "client",
				ClientSecret:   "client",
				RedirectionURL: "http://120.0.0.1",
				Upstream:       "http://120.0.0.1",
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "http://120.0.0.1",
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
			Ok: true,
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "http://120.0.0.1",
				MaxIdleConns:        0,
				MaxIdleConnsPerHost: 0,
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "http://120.0.0.1",
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 200,
			},
		},
		{
			Config: &Config{
				Listen:         ":8080",
				DiscoveryURL:   "http://127.0.0.1:8080",
				ClientID:       "client",
				ClientSecret:   "client",
				RedirectionURL: "http://120.0.0.1",
				Upstream:       "http://120.0.0.1",
				MatchClaims: map[string]string{
					"test": "&&&[",
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
		},
		{
			Config: &Config{
				Listen:                ":8080",
				SkipTokenVerification: true,
				Upstream:              "http://120.0.0.1",
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   50,
			},
			Ok: true,
		},
		{
			Config: &Config{
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "http://120.0.0.1",
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "this should fail",
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "this should fail",
				SecureCookie:        true,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "https://120.0.0.1",
				Upstream:            "http://someupstream",
				SecureCookie:        true,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
			Ok: true,
		},
	}

	for i, c := range tests {
		if err := c.Config.isValid(); err != nil && c.Ok {
			t.Errorf("test case %d, the config should not have errored, error: %s", i, err)
		}
	}
}

func TestIsListenValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidListen",
			Config: &Config{
				Listen: ":8080",
			},
			Valid: true,
		},
		{
			Name: "InValidListen",
			Config: &Config{
				Listen: "",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isListenValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsListenAdminSchemeValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "HTTPValidListenAdminScheme",
			Config: &Config{
				ListenAdminScheme: unsecureScheme,
			},
			Valid: true,
		},
		{
			Name: "HTTPSValidListenAdminScheme",
			Config: &Config{
				ListenAdminScheme: secureScheme,
			},
			Valid: true,
		},
		{
			Name: "InValidListenAdminScheme",
			Config: &Config{
				Listen: "",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isListenAdminSchemeValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsMaxIdlleConnValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidMaxIdleConns",
			Config: &Config{
				MaxIdleConns: 50,
			},
			Valid: true,
		},
		{
			Name: "ValidMaxIdleConnsPerHost",
			Config: &Config{
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 30,
			},
			Valid: true,
		},
		{
			Name: "NegativeInValidMaxIdleConns",
			Config: &Config{
				MaxIdleConns: -1,
			},
			Valid: false,
		},
		{
			Name: "NegativeInValidMaxIdleConnsPerHost",
			Config: &Config{
				MaxIdleConnsPerHost: -1,
			},
			Valid: false,
		},
		{
			Name: "GreaterThanMaxIdleConnsInValidMaxIdleConnsPerHost",
			Config: &Config{
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 100,
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isMaxIdlleConnValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsSameSiteValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "EmptyValidSameSiteCookie",
			Config: &Config{
				SameSiteCookie: "",
			},
			Valid: true,
		},
		{
			Name: "StrictValidSameSiteCookie",
			Config: &Config{
				SameSiteCookie: SameSiteStrict,
			},
			Valid: true,
		},
		{
			Name: "LaxValidSameSiteCookie",
			Config: &Config{
				SameSiteCookie: SameSiteLax,
			},
			Valid: true,
		},
		{
			Name: "NoneValidSameSiteCookie",
			Config: &Config{
				SameSiteCookie: SameSiteNone,
			},
			Valid: true,
		},
		{
			Name: "InvalidSameSiteCookie",
			Config: &Config{
				SameSiteCookie: "scrambled",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isSameSiteValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsTLSFilesValid(t *testing.T) {
	testCases := []struct {
		Name                       string
		Config                     *Config
		Valid                      bool
		TLSCertificateExists       bool
		TLSClientCertificateExists bool
		TLSPrivateKeyExists        bool
		TLSCaCertificateExists     bool
	}{
		{
			Name: "ValidPrivateAndCertificate",
			Config: &Config{
				TLSCertificate: fmt.Sprintf("/tmp/gateconfig_crt_%d", rand.Intn(10000)),
				TLSPrivateKey:  fmt.Sprintf("/tmp/gateconfig_priv_%d", rand.Intn(10000)),
			},
			Valid:                      true,
			TLSCertificateExists:       true,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        true,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingPrivateFile",
			Config: &Config{
				TLSCertificate: fmt.Sprintf("/tmp/gateconfig_crt_%d", rand.Intn(10000)),
				TLSPrivateKey:  fmt.Sprintf("/tmp/gateconfig_priv_%d", rand.Intn(10000)),
			},
			Valid:                      false,
			TLSCertificateExists:       true,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        false,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingPrivate",
			Config: &Config{
				TLSCertificate: fmt.Sprintf("/tmp/gateconfig_crt_%d", rand.Intn(10000)),
				TLSPrivateKey:  "",
			},
			Valid:                      false,
			TLSCertificateExists:       true,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        false,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingCertificateFile",
			Config: &Config{
				TLSCertificate: fmt.Sprintf("/tmp/gateconfig_crt_%d", rand.Intn(10000)),
				TLSPrivateKey:  fmt.Sprintf("/tmp/gateconfig_priv_%d", rand.Intn(10000)),
			},
			Valid:                      false,
			TLSCertificateExists:       false,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        true,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingCertificate",
			Config: &Config{
				TLSCertificate: "",
				TLSPrivateKey:  fmt.Sprintf("/tmp/gateconfig_priv_%d", rand.Intn(10000)),
			},
			Valid:                      false,
			TLSCertificateExists:       false,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        true,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingPrivateAndCertificateFile",
			Config: &Config{
				TLSCertificate: fmt.Sprintf("/tmp/gateconfig_crt_%d", rand.Intn(10000)),
				TLSPrivateKey:  fmt.Sprintf("/tmp/gateconfig_priv_%d", rand.Intn(10000)),
			},
			Valid:                      false,
			TLSCertificateExists:       false,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        false,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "ValidCaCertificate",
			Config: &Config{
				TLSCaCertificate: fmt.Sprintf("/tmp/gateconfig_ca_%d", rand.Intn(10000)),
			},
			Valid:                      true,
			TLSCertificateExists:       false,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        false,
			TLSCaCertificateExists:     true,
		},
		{
			Name: "InValidMissingCaCertificateFile",
			Config: &Config{
				TLSCaCertificate: fmt.Sprintf("/tmp/gateconfig_ca_%d", rand.Intn(10000)),
			},
			Valid:                      false,
			TLSCertificateExists:       false,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        false,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "ValidClientCertificate",
			Config: &Config{
				TLSClientCertificate: fmt.Sprintf("/tmp/gateconfig_client_%d", rand.Intn(10000)),
			},
			Valid:                      true,
			TLSCertificateExists:       false,
			TLSClientCertificateExists: true,
			TLSPrivateKeyExists:        false,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "InvalidValidMissingClientCertificate",
			Config: &Config{
				TLSClientCertificate: fmt.Sprintf("/tmp/gateconfig_client_%d", rand.Intn(10000)),
			},
			Valid:                      false,
			TLSCertificateExists:       false,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        false,
			TLSCaCertificateExists:     false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				certFile := ""
				clientCertFile := ""
				privFile := ""
				caFile := ""
				c := testCase.Config

				if c.TLSCertificate != "" {
					certFile = c.TLSCertificate
				}

				if c.TLSClientCertificate != "" {
					clientCertFile = c.TLSClientCertificate
				}

				if c.TLSPrivateKey != "" {
					privFile = c.TLSPrivateKey
				}

				if c.TLSCaCertificate != "" {
					caFile = c.TLSCaCertificate
				}

				if certFile != "" && testCase.TLSCertificateExists {
					err := ioutil.WriteFile(certFile, []byte(""), 0644)

					if err != nil {
						t.Fatalf("Problem writing certificate %s", err)
					}
					defer os.Remove(certFile)
				}

				if clientCertFile != "" && testCase.TLSClientCertificateExists {
					err := ioutil.WriteFile(clientCertFile, []byte(""), 0644)

					if err != nil {
						t.Fatalf("Problem writing certificate %s", err)
					}
					defer os.Remove(certFile)
				}

				if privFile != "" && testCase.TLSPrivateKeyExists {
					err := ioutil.WriteFile(privFile, []byte(""), 0644)

					if err != nil {
						t.Fatalf("Problem writing privateKey %s", err)
					}
					defer os.Remove(privFile)
				}

				if caFile != "" && testCase.TLSCaCertificateExists {
					err := ioutil.WriteFile(caFile, []byte(""), 0644)

					if err != nil {
						t.Fatalf("Problem writing cacertificate %s", err)
					}
					defer os.Remove(caFile)
				}

				err := testCase.Config.isTLSFilesValid()

				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsAdminTLSFilesValid(t *testing.T) {
	testCases := []struct {
		Name                            string
		Config                          *Config
		Valid                           bool
		TLSAdminCertificateExists       bool
		TLSAdminClientCertificateExists bool
		TLSAdminPrivateKeyExists        bool
		TLSAdminCaCertificateExists     bool
	}{
		{
			Name: "ValidPrivateAndCertificate",
			Config: &Config{
				TLSAdminCertificate: fmt.Sprintf("/tmp/gateadminconfig_crt_%d", rand.Intn(10000)),
				TLSAdminPrivateKey:  fmt.Sprintf("/tmp/gateadminconfig_priv_%d", rand.Intn(10000)),
			},
			Valid:                           true,
			TLSAdminCertificateExists:       true,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        true,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingPrivateFile",
			Config: &Config{
				TLSAdminCertificate: fmt.Sprintf("/tmp/gateadminconfig_crt_%d", rand.Intn(10000)),
				TLSAdminPrivateKey:  fmt.Sprintf("/tmp/gateadminconfig_priv_%d", rand.Intn(10000)),
			},
			Valid:                           false,
			TLSAdminCertificateExists:       true,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        false,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingPrivate",
			Config: &Config{
				TLSAdminCertificate: fmt.Sprintf("/tmp/gateadminconfig_crt_%d", rand.Intn(10000)),
				TLSAdminPrivateKey:  "",
			},
			Valid:                           false,
			TLSAdminCertificateExists:       true,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        false,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingCertificateFile",
			Config: &Config{
				TLSAdminCertificate: fmt.Sprintf("/tmp/gateadminconfig_crt_%d", rand.Intn(10000)),
				TLSAdminPrivateKey:  fmt.Sprintf("/tmp/gateadminconfig_priv_%d", rand.Intn(10000)),
			},
			Valid:                           false,
			TLSAdminCertificateExists:       false,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        true,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingCertificate",
			Config: &Config{
				TLSAdminCertificate: "",
				TLSAdminPrivateKey:  fmt.Sprintf("/tmp/gateadminconfig_priv_%d", rand.Intn(10000)),
			},
			Valid:                           false,
			TLSAdminCertificateExists:       false,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        true,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingPrivateAndCertificateFile",
			Config: &Config{
				TLSAdminCertificate: fmt.Sprintf("/tmp/gateadminconfig_crt_%d", rand.Intn(10000)),
				TLSAdminPrivateKey:  fmt.Sprintf("/tmp/gateadminconfig_priv_%d", rand.Intn(10000)),
			},
			Valid:                           false,
			TLSAdminCertificateExists:       false,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        false,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "ValidCaCertificate",
			Config: &Config{
				TLSAdminCaCertificate: fmt.Sprintf("/tmp/gateadminconfig_ca_%d", rand.Intn(10000)),
			},
			Valid:                           true,
			TLSAdminCertificateExists:       false,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        false,
			TLSAdminCaCertificateExists:     true,
		},
		{
			Name: "InValidMissingCaCertificateFile",
			Config: &Config{
				TLSAdminCaCertificate: fmt.Sprintf("/tmp/gateadminconfig_ca_%d", rand.Intn(10000)),
			},
			Valid:                           false,
			TLSAdminCertificateExists:       false,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        false,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "ValidClientCertificate",
			Config: &Config{
				TLSAdminClientCertificate: fmt.Sprintf("/tmp/gateadminconfig_client_%d", rand.Intn(10000)),
			},
			Valid:                           true,
			TLSAdminCertificateExists:       false,
			TLSAdminClientCertificateExists: true,
			TLSAdminPrivateKeyExists:        false,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "InvalidValidMissingClientCertificate",
			Config: &Config{
				TLSAdminClientCertificate: fmt.Sprintf("/tmp/gateadminconfig_client_%d", rand.Intn(10000)),
			},
			Valid:                           false,
			TLSAdminCertificateExists:       false,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        false,
			TLSAdminCaCertificateExists:     false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				certFile := ""
				clientCertFile := ""
				privFile := ""
				caFile := ""
				c := testCase.Config

				if c.TLSAdminCertificate != "" {
					certFile = c.TLSAdminCertificate
				}

				if c.TLSAdminClientCertificate != "" {
					clientCertFile = c.TLSAdminClientCertificate
				}

				if c.TLSAdminPrivateKey != "" {
					privFile = c.TLSAdminPrivateKey
				}

				if c.TLSAdminCaCertificate != "" {
					caFile = c.TLSAdminCaCertificate
				}

				if certFile != "" && testCase.TLSAdminCertificateExists {
					err := ioutil.WriteFile(certFile, []byte(""), 0644)

					if err != nil {
						t.Fatalf("Problem writing certificate %s", err)
					}
					defer os.Remove(certFile)
				}

				if clientCertFile != "" && testCase.TLSAdminClientCertificateExists {
					err := ioutil.WriteFile(clientCertFile, []byte(""), 0644)

					if err != nil {
						t.Fatalf("Problem writing certificate %s", err)
					}
					defer os.Remove(certFile)
				}

				if privFile != "" && testCase.TLSAdminPrivateKeyExists {
					err := ioutil.WriteFile(privFile, []byte(""), 0644)

					if err != nil {
						t.Fatalf("Problem writing privateKey %s", err)
					}
					defer os.Remove(privFile)
				}

				if caFile != "" && testCase.TLSAdminCaCertificateExists {
					err := ioutil.WriteFile(caFile, []byte(""), 0644)

					if err != nil {
						t.Fatalf("Problem writing cacertificate %s", err)
					}
					defer os.Remove(caFile)
				}

				err := testCase.Config.isAdminTLSFilesValid()

				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsLetsEncryptValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "NotUseValidUseLetsEncrypt",
			Config: &Config{
				UseLetsEncrypt: false,
			},
			Valid: true,
		},
		{
			Name: "ValidUseLetsEncryptWithCacheDir",
			Config: &Config{
				UseLetsEncrypt:      true,
				LetsEncryptCacheDir: "/somedir",
			},
			Valid: true,
		},
		{
			Name: "InvalidUseLetsEncrypt",
			Config: &Config{
				UseLetsEncrypt:      true,
				LetsEncryptCacheDir: "",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isLetsEncryptValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsForwardingProxySettingsValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidForwardingProxySettings",
			Config: &Config{
				EnableForwarding:    true,
				ClientID:            "some-client",
				DiscoveryURL:        "https://somediscoveryurl",
				ForwardingGrantType: GrantTypeUserCreds,
				ForwardingUsername:  "someuser",
				ForwardingPassword:  "somepass",
			},
			Valid: true,
		},
		{
			Name: "ValidForwardingProxySettingsDisabledForwarding",
			Config: &Config{
				EnableForwarding: false,
			},
			Valid: true,
		},
		{
			Name: "InValidForwardingProxySettingsMissingClientID",
			Config: &Config{
				EnableForwarding:    true,
				ClientID:            "",
				DiscoveryURL:        "https://somediscoveryurl",
				ForwardingGrantType: GrantTypeUserCreds,
				ForwardingUsername:  "someuser",
				ForwardingPassword:  "somepass",
			},
			Valid: false,
		},
		{
			Name: "InValidForwardingProxySettingsRedundantTLSCertificate",
			Config: &Config{
				EnableForwarding:    true,
				ClientID:            "some-client",
				DiscoveryURL:        "https://somediscoveryurl",
				ForwardingGrantType: GrantTypeUserCreds,
				ForwardingUsername:  "someuser",
				ForwardingPassword:  "somepass",
				TLSCertificate:      "/sometest",
			},
			Valid: false,
		},
		{
			Name: "InValidForwardingProxySettingsRedundantTLSPrivateKey",
			Config: &Config{
				EnableForwarding:    true,
				ClientID:            "some-client",
				DiscoveryURL:        "https://somediscoveryurl",
				ForwardingGrantType: GrantTypeUserCreds,
				ForwardingUsername:  "someuser",
				ForwardingPassword:  "somepass",
				TLSPrivateKey:       "/sometest",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isForwardingProxySettingsValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsReverseProxySettingsValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidReverseProxySettings",
			Config: &Config{
				EnableForwarding: false,
				ClientID:         "some-client",
				DiscoveryURL:     "https://somediscoveryurl",
				Upstream:         "https://test.com",
			},
			Valid: true,
		},
		{
			Name: "ValidReverseProxySettingsDisabled",
			Config: &Config{
				EnableForwarding: true,
			},
			Valid: true,
		},
		{
			Name: "InValidReverseProxySettings",
			Config: &Config{
				EnableForwarding: false,
				ClientID:         "some-client",
				DiscoveryURL:     "https://somediscoveryurl",
				Upstream:         "",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isReverseProxySettingsValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsTokenVerificationSettingsValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidTokenVerificationSettings",
			Config: &Config{
				SkipTokenVerification: false,
				ClientID:              "some-client",
				DiscoveryURL:          "https://somediscoveryurl",
			},
			Valid: true,
		},
		{
			Name: "ValidTokenVerificationSettingsSkipVerification",
			Config: &Config{
				SkipTokenVerification: true,
			},
			Valid: true,
		},
		{
			Name: "InValidTokenVerificationSettings",
			Config: &Config{
				SkipTokenVerification: false,
				ClientID:              "some-client",
				DiscoveryURL:          "https://somediscoveryurl",
				EnableRefreshTokens:   true,
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isTokenVerificationSettingsValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsTLSMinValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidEmptyTLS",
			Config: &Config{
				TLSMinVersion: "",
			},
			Valid: true,
		},
		{
			Name: "ValidTLS1.0",
			Config: &Config{
				TLSMinVersion: "tlsv1.0",
			},
			Valid: true,
		},
		{
			Name: "ValidTLS1.1",
			Config: &Config{
				TLSMinVersion: "tlsv1.1",
			},
			Valid: true,
		},
		{
			Name: "ValidTLS1.2",
			Config: &Config{
				TLSMinVersion: "tlsv1.2",
			},
			Valid: true,
		},
		{
			Name: "ValidTLS1.3",
			Config: &Config{
				TLSMinVersion: "tlsv1.3",
			},
			Valid: true,
		},
		{
			Name: "InvalidTLS",
			Config: &Config{
				TLSMinVersion: "tlsv1.4",
			},
			Valid: false,
		},
		{
			Name: "InvalidTLS",
			Config: &Config{
				TLSMinVersion: "eddredd",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isTLSMinValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsUpstreamValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidUpstream",
			Config: &Config{
				Upstream: "http://aklsdsdo",
			},
			Valid: true,
		},
		{
			Name: "InValidUpstreamEmpty",
			Config: &Config{
				Upstream: "",
			},
			Valid: false,
		},
		{
			Name: "InValidUpstreamInvalidURI",
			Config: &Config{
				Upstream: "asas",
			},
			Valid: false,
		},
		{
			Name: "InValidSkipUpstreamTLSVerify",
			Config: &Config{
				Upstream:              "http://ssss",
				SkipUpstreamTLSVerify: true,
				UpstreamCA:            "/ssss",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isUpstreamValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsClientIDValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidClientID",
			Config: &Config{
				ClientID: "some-client",
			},
			Valid: true,
		},
		{
			Name: "InValidClientID",
			Config: &Config{
				ClientID: "",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isClientIDValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsDiscoveryURLValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidDiscoveryURL",
			Config: &Config{
				DiscoveryURL: "someurl",
			},
			Valid: true,
		},
		{
			Name: "InValidDiscoveryURL",
			Config: &Config{
				DiscoveryURL: "",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isDiscoveryURLValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsForwardingGrantValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidForwardingGrantTypeUserCreds",
			Config: &Config{
				ForwardingGrantType: GrantTypeUserCreds,
				ForwardingUsername:  "someuser",
				ForwardingPassword:  "somepass",
			},
			Valid: true,
		},
		{
			Name: "InValidForwardingGrantTypeUserCredsMissingUsername",
			Config: &Config{
				ForwardingGrantType: GrantTypeUserCreds,
				ForwardingUsername:  "",
				ForwardingPassword:  "somepass",
			},
			Valid: false,
		},
		{
			Name: "InValidForwardingGrantTypeUserCredsMissingPassword",
			Config: &Config{
				ForwardingGrantType: GrantTypeUserCreds,
				ForwardingUsername:  "",
				ForwardingPassword:  "somepass",
			},
			Valid: false,
		},
		{
			Name: "InValidForwardingGrantTypeUserCredsBoth",
			Config: &Config{
				ForwardingGrantType: GrantTypeUserCreds,
				ForwardingUsername:  "",
				ForwardingPassword:  "",
			},
			Valid: false,
		},
		{
			Name: "ValidForwardingGrantTypeClientCreds",
			Config: &Config{
				ForwardingGrantType: GrantTypeClientCreds,
				ClientSecret:        "somesecret",
			},
			Valid: true,
		},
		{
			Name: "InValidForwardingGrantTypeClientCreds",
			Config: &Config{
				ForwardingGrantType: GrantTypeClientCreds,
				ClientSecret:        "",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isForwardingGrantValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsSecurityFilterValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidSecurityFilterSettings",
			Config: &Config{
				EnableHTTPSRedirect:    true,
				EnableBrowserXSSFilter: true,
				EnableFrameDeny:        true,
				ContentSecurityPolicy:  "default-src 'self'",
				Hostnames:              []string{"test"},
				EnableSecurityFilter:   true,
			},
			Valid: true,
		},
		{
			Name: "InValidSecurityFilterSettingsEnableHTTPSRedirect",
			Config: &Config{
				EnableHTTPSRedirect:  true,
				EnableSecurityFilter: false,
			},
			Valid: false,
		},
		{
			Name: "InValidSecurityFilterSettingsEnableBrowserXSSFilter",
			Config: &Config{
				EnableBrowserXSSFilter: true,
				EnableSecurityFilter:   false,
			},
			Valid: false,
		},
		{
			Name: "InValidSecurityFilterSettingsEnableFrameDeny",
			Config: &Config{
				EnableFrameDeny:      true,
				EnableSecurityFilter: false,
			},
			Valid: false,
		},
		{
			Name: "InValidSecurityFilterSettingsContentSecurityPolicy",
			Config: &Config{
				ContentSecurityPolicy: "default-src 'self'",
				EnableSecurityFilter:  false,
			},
			Valid: false,
		},
		{
			Name: "InValidSecurityFilterSettingsContentSecurityPolicy",
			Config: &Config{
				Hostnames:            []string{"test"},
				EnableSecurityFilter: false,
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isSecurityFilterValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsTokenEncryptionValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidTokenEncryptionSettings",
			Config: &Config{
				EnableEncryptedToken: true,
				ForceEncryptedCookie: true,
				EncryptionKey:        "sdkljfalisujeoir",
				EnableRefreshTokens:  true,
			},
			Valid: true,
		},
		{
			Name: "InValidTokenEncryptionEncryptedTokenMissingEncryptionKey",
			Config: &Config{
				EnableEncryptedToken: true,
				ForceEncryptedCookie: true,
				EncryptionKey:        "",
			},
			Valid: false,
		},
		{
			Name: "InValidTokenEncryptionForceEncryptedCookieMissingEncryptionKey",
			Config: &Config{
				ForceEncryptedCookie: true,
				EncryptionKey:        "",
			},
			Valid: false,
		},
		{
			Name: "InValidTokenEncryptionEnableRefreshTokensMissingEncryptionKey",
			Config: &Config{
				EnableRefreshTokens: true,
				EncryptionKey:       "",
			},
			Valid: false,
		},
		{
			Name: "InValidTokenEncryptionEnableRefreshTokensInvalidEncryptionKey",
			Config: &Config{
				EnableRefreshTokens: true,
				EncryptionKey:       "ssdsds",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isTokenEncryptionValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsSecureCookieValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidSecureCookie",
			Config: &Config{
				NoRedirects:    false,
				SecureCookie:   true,
				RedirectionURL: "https://someredirectionurl",
			},
			Valid: true,
		},
		{
			Name: "InValidSecureCookie",
			Config: &Config{
				NoRedirects:    false,
				SecureCookie:   true,
				RedirectionURL: "http://someredirectionurl",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isSecureCookieValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsStoreURLValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidIsStoreURL",
			Config: &Config{
				StoreURL: "boltdb:////tmp/test.boltdb",
			},
			Valid: true,
		},
		{
			Name: "InValidIsStoreURL",
			Config: &Config{
				StoreURL: "kwoie",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isStoreURLValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsResourceValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidResource",
			Config: &Config{
				Resources: []*Resource{
					{
						URL:     fakeAdminRoleURL,
						Methods: []string{"GET"},
						Roles:   []string{fakeAdminRole},
					},
					{
						URL:     fakeTestAdminRolesURL,
						Methods: []string{"GET"},
						Roles:   []string{fakeAdminRole, fakeTestRole},
					},
				},
			},
			Valid: true,
		},
		{
			Name: "ValidResourceWithCustomHTTP",
			Config: &Config{
				CustomHTTPMethods: []string{"SOME"},
				Resources: []*Resource{
					{
						URL:     fakeAdminRoleURL,
						Methods: []string{"SOME"},
						Roles:   []string{fakeAdminRole},
					},
					{
						URL:     fakeTestAdminRolesURL,
						Methods: []string{"GET"},
						Roles:   []string{fakeAdminRole, fakeTestRole},
					},
				},
			},
			Valid: true,
		},
		{
			Name: "InValidResourceWithCustomHTTP",
			Config: &Config{
				Resources: []*Resource{
					{
						URL:     fakeAdminRoleURL,
						Methods: []string{"SOMER"},
						Roles:   []string{fakeAdminRole},
					},
					{
						URL:     fakeTestAdminRolesURL,
						Methods: []string{"GET"},
						Roles:   []string{fakeAdminRole, fakeTestRole},
					},
				},
			},
			Valid: false,
		},
		{
			Name: "InValidResourceMissingURL",
			Config: &Config{
				Resources: []*Resource{
					{
						URL:     "",
						Methods: []string{"GET"},
						Roles:   []string{fakeAdminRole},
					},
					{
						URL:     fakeTestAdminRolesURL,
						Methods: []string{"GET"},
						Roles:   []string{fakeAdminRole, fakeTestRole},
					},
				},
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isResourceValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsMatchClaimValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidMatchClaim",
			Config: &Config{
				MatchClaims: map[string]string{
					"test": "/some[0-9]/",
				},
			},
			Valid: true,
		},
		{
			Name: "InValidMatchClaim",
			Config: &Config{
				MatchClaims: map[string]string{
					"test": "&&&[",
				},
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isMatchClaimValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}
