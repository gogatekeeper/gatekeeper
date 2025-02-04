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

package testsuite_test

import (
	"context"
	"testing"
	"time"

	"golang.org/x/oauth2"

	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetUserinfo(t *testing.T) {
	proxy, idp, _ := newTestProxyService(nil)
	token, err := NewTestToken(idp.getLocation()).GetToken()
	require.NoError(t, err)
	tokenSource := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)

	ctx, cancel := context.WithTimeout(context.Background(), proxy.Config.OpenIDProviderTimeout)
	defer cancel()

	userInfo, err := proxy.Provider.UserInfo(ctx, tokenSource)
	require.NoError(t, err)

	claims := DefaultTestTokenClaims{}
	err = userInfo.Claims(&claims)

	require.NoError(t, err)
	assert.NotEqual(t, (DefaultTestTokenClaims{}), claims)
}

func TestTokenExpired(t *testing.T) {
	proxy, idp, _ := newTestProxyService(nil)
	token := NewTestToken(idp.getLocation())
	testCases := []struct {
		Expire time.Duration
		OK     bool
	}{
		{
			Expire: 1 * time.Hour,
			OK:     true,
		},
		{
			Expire: -5 * time.Hour,
		},
	}
	for idx, testCase := range testCases {
		token.SetExpiration(time.Now().Add(testCase.Expire))
		jwt, err := token.GetToken()
		if err != nil {
			t.Errorf("case %d unable to sign the token, error: %s", idx, err)
			continue
		}

		verifier := proxy.Provider.Verifier(
			&oidc3.Config{
				ClientID:          proxy.Config.ClientID,
				SkipClientIDCheck: true,
			},
		)
		_, err = verifier.Verify(context.Background(), jwt)

		if testCase.OK && err != nil {
			t.Errorf("case %d, expected: %t got error: %s", idx, testCase.OK, err)
		}
		if !testCase.OK && err == nil {
			t.Errorf("case %d, expected: %t got no error", idx, testCase.OK)
		}
	}
}
