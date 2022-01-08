// +build e2e

package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	resty "github.com/go-resty/resty/v2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	testRealm        = "test"
	testClient       = "test-client"
	testClientSecret = "6447d0c0-d510-42a7-b654-6e3a16b2d7e2"
)

func TestMain(m *testing.M) {
	retry := 0

	operation := func() error {
		var err error

		if retry > 0 {
			fmt.Printf("Retrying connection to keycloak instance %d", retry)
		}

		client := resty.New()
		request := client.R()
		resp, err := request.Execute("GET", "http://localhost:8081")

		status := resp.StatusCode()

		if status != 200 {
			retry++
			return err
		}

		return nil
	}

	backOff := backoff.NewExponentialBackOff()
	backOff.MaxElapsedTime = time.Second * 300
	err := backoff.Retry(operation, backOff)

	if err != nil {
		fmt.Print("Failed to connect to keycloak instance, aborting!")
		os.Exit(1)
	}

	time.Sleep(30 * time.Second)

	code := m.Run()
	os.Exit(code)
}

func TestE2E(t *testing.T) {
	server := httptest.NewServer(&fakeUpstreamService{})
	rand.Seed(time.Now().UnixNano())
	min := 1024
	max := 65000
	portNum := fmt.Sprintf("%d", rand.Intn(max-min+1)+min)

	os.Setenv("PROXY_DISCOVERY_URL", "http://localhost:8081/auth/realms/"+testRealm)
	os.Setenv("PROXY_OPENID_PROVIDER_TIMEOUT", "60s")
	os.Setenv("PROXY_LISTEN", "0.0.0.0:"+portNum)
	os.Setenv("PROXY_CLIENT_ID", testClient)
	os.Setenv("PROXY_CLIENT_SECRET", testClientSecret)
	os.Setenv("PROXY_UPSTREAM_URL", server.URL)
	os.Setenv("PROXY_NO_REDIRECTS", "true")
	os.Setenv("PROXY_SKIP_ACCESS_TOKEN_CLIENT_ID_CHECK", "true")
	os.Setenv("PROXY_SKIP_ACCESS_TOKEN_ISSUER_CHECK", "true")

	go func() {
		app := newOauthProxyApp()
		os.Args = []string{os.Args[0]}
		err := app.Run(os.Args)

		if err != nil {
			log.Fatalf("Error during e2e test %s", err)
			os.Exit(1)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conf := &clientcredentials.Config{
		ClientID:     testClient,
		ClientSecret: testClientSecret,
		Scopes:       []string{"email", "openid"},
		TokenURL:     "http://localhost:8081/auth/realms/" + testRealm + "/protocol/openid-connect/token",
	}

	respToken, err := conf.Token(ctx)

	if err != nil {
		t.Fatalf("Failed to acquire access token for client")
	}

	retry := 0

	operation := func() error {
		var err error

		if retry > 0 {
			fmt.Printf("Retrying connection to proxy instance %d", retry)
		}

		_, err = http.Get("http://localhost:" + portNum)

		if err != nil {
			return err
		}

		return nil
	}

	backOff := backoff.NewExponentialBackOff()
	backOff.MaxElapsedTime = time.Second * 300
	err = backoff.Retry(operation, backOff)

	if err != nil {
		fmt.Print("Failed to connect to proxy instance, aborting!")
		os.Exit(1)
	}

	client := resty.New()
	request := client.SetRedirectPolicy(resty.NoRedirectPolicy()).R()
	request.SetAuthToken(respToken.AccessToken)

	resp, err := request.Execute("GET", "http://localhost:"+portNum)

	if err != nil {
		t.Fatalf("Failed to connect to proxy instance, aborting!")
	}

	status := resp.StatusCode()

	if status != 200 {
		t.Fatalf("Bad response code %d", status)
	}
}
