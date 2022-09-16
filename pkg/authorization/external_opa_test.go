package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	opaserver "github.com/open-policy-agent/opa/server"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

type OpaTestInput struct {
	Name    string `json:"name" yaml:"name"`
	Surname string `json:"surname" yaml:"surname"`
}

//nolint:funlen,cyclop
func TestExternalOpa(t *testing.T) {
	requests := []struct {
		Name           string
		FakeRequest    func() (*http.Request, error)
		AuthzPolicy    string
		StartOpa       bool
		ExpectedResult AuthzDecision
		ExptectError   bool
	}{
		{
			Name: "AuthorizedRequest",
			FakeRequest: func() (*http.Request, error) {
				testInput := &OpaTestInput{
					Name: "Test",
				}
				reqBody, err := json.Marshal(testInput)

				if err != nil {
					return nil, err
				}

				httpReq, err := http.NewRequest(
					http.MethodPost,
					"dummy",
					bytes.NewReader(reqBody),
				)

				if err != nil {
					return nil, err
				}

				return httpReq, nil
			},
			AuthzPolicy: `
			package authz

			default allow := false

			body := json.unmarshal(input.body)
			allow {
				body.name = "Test"
			}
			`,
			StartOpa:       true,
			ExpectedResult: AllowedAuthz,
		},
		{
			Name: "NonAuthorizedRequest",
			FakeRequest: func() (*http.Request, error) {
				testInput := &OpaTestInput{
					Name: "Test",
				}
				reqBody, err := json.Marshal(testInput)

				if err != nil {
					return nil, err
				}

				httpReq, err := http.NewRequest(
					http.MethodPost,
					"dummy",
					bytes.NewReader(reqBody),
				)

				if err != nil {
					return nil, err
				}

				return httpReq, nil
			},
			AuthzPolicy: `
			package authz

			default allow := false

			body := json.unmarshal(input.body)
			allow {
				body.name = "Tester"
			}
			`,
			StartOpa:       true,
			ExpectedResult: DeniedAuthz,
		},
		{
			Name: "OpaPolicyMissing",
			FakeRequest: func() (*http.Request, error) {
				testInput := &OpaTestInput{
					Name: "Test",
				}
				reqBody, err := json.Marshal(testInput)

				if err != nil {
					return nil, err
				}

				httpReq, err := http.NewRequest(
					http.MethodPost,
					"dummy",
					bytes.NewReader(reqBody),
				)

				if err != nil {
					return nil, err
				}

				return httpReq, nil
			},
			AuthzPolicy:    ``,
			StartOpa:       true,
			ExpectedResult: DeniedAuthz,
		},
		{
			Name: "OpaServerNotStarted",
			FakeRequest: func() (*http.Request, error) {
				testInput := &OpaTestInput{
					Name: "Test",
				}
				reqBody, err := json.Marshal(testInput)

				if err != nil {
					return nil, err
				}

				httpReq, err := http.NewRequest(
					http.MethodPost,
					"dummy",
					bytes.NewReader(reqBody),
				)

				if err != nil {
					return nil, err
				}

				return httpReq, nil
			},
			AuthzPolicy:    ``,
			StartOpa:       false,
			ExpectedResult: DeniedAuthz,
			ExptectError:   true,
		},
		{
			Name: "AuthorizedRequestYAMLBody",
			FakeRequest: func() (*http.Request, error) {
				testInput := &OpaTestInput{
					Name: "Test",
				}
				reqBody, err := yaml.Marshal(testInput)

				if err != nil {
					return nil, err
				}

				httpReq, err := http.NewRequest(
					http.MethodPost,
					"dummy",
					bytes.NewReader(reqBody),
				)

				if err != nil {
					return nil, err
				}

				return httpReq, nil
			},
			AuthzPolicy: `
			package authz

			default allow := false

			body := yaml.unmarshal(input.body)
			allow {
				body.name = "Test"
			}
			`,
			StartOpa:       true,
			ExpectedResult: AllowedAuthz,
		},
		{
			Name: "AuthorizedRequestMatchingHeaders",
			FakeRequest: func() (*http.Request, error) {
				testInput := &OpaTestInput{
					Name: "Test",
				}
				reqBody, err := yaml.Marshal(testInput)

				if err != nil {
					return nil, err
				}

				httpReq, err := http.NewRequest(
					http.MethodPost,
					"dummy",
					bytes.NewReader(reqBody),
				)

				if err != nil {
					return nil, err
				}

				httpReq.Header.Add("X-CUSTOM", "TESTVALUE")
				return httpReq, nil
			},
			AuthzPolicy: `
			package authz
		
			default allow := false
		
			body := yaml.unmarshal(input.body)
			allow {
				body.name = "Test"
				input.headers["X-Custom"][0] = "TESTVALUE"
			}
			`,
			StartOpa:       true,
			ExpectedResult: AllowedAuthz,
		},
	}

	for _, testCase := range requests {
		testCase := testCase
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				ctx := context.Background()
				authzPolicy := testCase.AuthzPolicy
				opaAddress := ""
				var server *opaserver.Server

				if testCase.StartOpa {
					server = StartOpaServer(ctx, t, authzPolicy)
					addrs := server.Addrs()
					opaAddress = addrs[0]
				}

				authzURI := fmt.Sprintf(
					"http://%s/%s",
					opaAddress,
					"v1/data/authz/allow",
				)
				authzURL, err := url.ParseRequestURI(authzURI)

				if err != nil {
					t.Fatalf("problem parsing authzURL")
				}

				req, err := testCase.FakeRequest()

				if err != nil {
					t.Fatal(err)
				}

				opaAuthzProvider := NewOpaAuthorizationProvider(
					10*time.Second,
					*authzURL,
					req,
				)

				decision, err := opaAuthzProvider.Authorize()

				assert.Equal(t, testCase.ExpectedResult, decision)

				if err != nil && !testCase.ExptectError {
					t.Fatal(err)
				}

				if testCase.StartOpa {
					err = server.Shutdown(ctx)

					if err != nil {
						t.Fatal(err)
					}
				}
			},
		)
	}
}
