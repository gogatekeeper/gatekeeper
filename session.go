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
	"net/http"
	"strings"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
	"gopkg.in/square/go-jose.v2/jwt"
)

// getIdentity retrieves the user identity from a request, either from a session cookie or a bearer token
func (r *oauthProxy) getIdentity(req *http.Request) (*userContext, error) {
	var isBearer bool
	// step: check for a bearer token or cookie with jwt token
	access, isBearer, err := utils.GetTokenInRequest(
		req,
		r.config.CookieAccessName,
		r.config.SkipAuthorizationHeaderIdentity,
	)

	if err != nil {
		return nil, err
	}

	if r.config.EnableEncryptedToken || r.config.ForceEncryptedCookie && !isBearer {
		if access, err = utils.DecodeText(access, r.config.EncryptionKey); err != nil {
			return nil, apperrors.ErrDecryption
		}
	}

	rawToken := access
	token, err := jwt.ParseSigned(access)

	if err != nil {
		return nil, err
	}

	user, err := extractIdentity(token)
	if err != nil {
		return nil, err
	}

	user.bearerToken = isBearer
	user.rawToken = rawToken

	r.log.Debug("found the user identity",
		zap.String("id", user.id),
		zap.String("name", user.name),
		zap.String("email", user.email),
		zap.String("roles", strings.Join(user.roles, ",")),
		zap.String("groups", strings.Join(user.groups, ",")))

	return user, nil
}

// extractIdentity parse the jwt token and extracts the various elements is order to construct
func extractIdentity(token *jwt.JSONWebToken) (*userContext, error) {
	stdClaims := &jwt.Claims{}

	type RealmRoles struct {
		Roles []string `json:"roles"`
	}

	// Extract custom claims
	type custClaims struct {
		Email          string                    `json:"email"`
		PrefName       string                    `json:"preferred_username"`
		RealmAccess    RealmRoles                `json:"realm_access"`
		Groups         []string                  `json:"groups"`
		ResourceAccess map[string]interface{}    `json:"resource_access"`
		FamilyName     string                    `json:"family_name"`
		GivenName      string                    `json:"given_name"`
		Username       string                    `json:"username"`
		Authorization  authorization.Permissions `json:"authorization"`
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
		scopes, assertOk := list.(map[string]interface{})

		if !assertOk {
			return nil, fmt.Errorf("assertion failed")
		}

		if roles, found := scopes[constant.ClaimResourceRoles]; found {
			rolesVal, assertOk := roles.([]interface{})

			if !assertOk {
				return nil, fmt.Errorf("assertion failed")
			}

			for _, r := range rolesVal {
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
		permissions:   customClaims.Authorization,
	}, nil
}

// isExpired checks if the token has expired
func (r *userContext) isExpired() bool {
	return r.expiresAt.Before(time.Now())
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
