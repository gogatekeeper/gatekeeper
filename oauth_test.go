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
	"context"
	"testing"
	"time"

	"golang.org/x/oauth2"

	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
)

func TestGetUserinfo(t *testing.T) {
	px, idp, _ := newTestProxyService(nil)
	token, err := newTestToken(idp.getLocation()).getToken()
	assert.NoError(t, err)
	tokenSource := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)

	ctx, cancel := context.WithTimeout(context.Background(), px.config.OpenIDProviderTimeout)
	defer cancel()

	userInfo, err := px.provider.UserInfo(ctx, tokenSource)
	assert.NoError(t, err)

	claims := DefaultTestTokenClaims{}
	err = userInfo.Claims(&claims)

	assert.NoError(t, err)
	assert.NotEqual(t, (DefaultTestTokenClaims{}), claims)
}

func TestTokenExpired(t *testing.T) {
	px, idp, _ := newTestProxyService(nil)
	token := newTestToken(idp.getLocation())
	cs := []struct {
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
	for i, x := range cs {
		token.setExpiration(time.Now().Add(x.Expire))
		jwt, err := token.getToken()
		if err != nil {
			t.Errorf("case %d unable to sign the token, error: %s", i, err)
			continue
		}

		verifier := px.provider.Verifier(
			&oidc3.Config{
				ClientID:          px.config.ClientID,
				SkipClientIDCheck: true,
			},
		)
		_, err = verifier.Verify(context.Background(), jwt)

		if x.OK && err != nil {
			t.Errorf("case %d, expected: %t got error: %s", i, x.OK, err)
		}
		if !x.OK && err == nil {
			t.Errorf("case %d, expected: %t got no error", i, x.OK)
		}
	}
}
