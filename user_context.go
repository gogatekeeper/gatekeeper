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
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
)

// extractIdentity parse the jwt token and extracts the various elements is order to construct
func extractIdentity(token *jwt.JSONWebToken) (*userContext, error) {
	stdClaims := &jwt.Claims{}

	type RealmRoles struct {
		Roles []string `json:"roles"`
	}

	// Extract custom claims
	type custClaims struct {
		Email          string                 `json:"email"`
		PrefName       string                 `json:"preferred_username"`
		RealmAccess    RealmRoles             `json:"realm_access"`
		Groups         []string               `json:"groups"`
		ResourceAccess map[string]interface{} `json:"resource_access"`
		FamilyName     string                 `json:"family_name"`
		GivenName      string                 `json:"given_name"`
		Username       string                 `json:"username"`
	}

	customClaims := custClaims{}

	err := token.UnsafeClaimsWithoutVerification(stdClaims, &customClaims)

	if err != nil {
		return nil, err
	}

	jsonMap := make(map[string]interface{})
	err = token.UnsafeClaimsWithoutVerification(&jsonMap)

	if err != nil {
		return nil, err
	}

	// @step: ensure we have and can extract the preferred name of the user, if not, we set to the ID
	preferredName := customClaims.PrefName
	if preferredName == "" {
		preferredName = customClaims.Email
	}

	audiences := stdClaims.Audience

	// @step: extract the realm roles
	roleList := make([]string, 0)
	roleList = append(roleList, customClaims.RealmAccess.Roles...)

	// @step: extract the client roles from the access token
	for name, list := range customClaims.ResourceAccess {
		scopes := list.(map[string]interface{})

		if roles, found := scopes[claimResourceRoles]; found {
			for _, r := range roles.([]interface{}) {
				roleList = append(roleList, fmt.Sprintf("%s:%s", name, r))
			}
		}
	}

	return &userContext{
		audiences:     audiences,
		email:         customClaims.Email,
		expiresAt:     stdClaims.Expiry.Time(),
		groups:        customClaims.Groups,
		id:            stdClaims.Subject,
		name:          preferredName,
		preferredName: preferredName,
		roles:         roleList,
		claims:        jsonMap,
	}, nil
}

// backported from https://github.com/coreos/go-oidc/blob/master/oidc/verification.go#L28-L37
// I'll raise another PR to make it public in the go-oidc package so we can just use `oidc.ContainsString()`
func containsString(needle string, haystack []string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// Deprecated:unused
// isAudience checks the audience
func (r *userContext) isAudience(aud string) bool {
	return containsString(aud, r.audiences)
}

// Deprecated:unused
// getRoles returns a list of roles
func (r *userContext) getRoles() string {
	return strings.Join(r.roles, ",")
}

// isExpired checks if the token has expired
func (r *userContext) isExpired() bool {
	return r.expiresAt.Before(time.Now())
}

// Deprecated:unused
// isBearer checks if the token
func (r *userContext) isBearer() bool {
	return r.bearerToken
}

// Deprecated:unused
// isCookie checks if it's by a cookie
func (r *userContext) isCookie() bool {
	return !r.isBearer()
}

// String returns a string representation of the user context
func (r *userContext) String() string {
	return fmt.Sprintf(
		"user: %s, expires: %s, roles: %s",
		r.preferredName,
		r.expiresAt.String(),
		strings.Join(r.roles, ","),
	)
}
