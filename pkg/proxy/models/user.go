package models

import (
	"fmt"
	"strings"
	"time"
)

type Permission struct {
	Scopes       []string `json:"scopes"`
	ResourceID   string   `json:"rsid"`
	ResourceName string   `json:"rsname"`
}

type Permissions struct {
	Permissions []Permission `json:"permissions"`
}

type RealmRoles struct {
	Roles []string `json:"roles"`
}

// Extract custom claims.
type CustClaims struct {
	Email          string                 `json:"email"`
	Acr            string                 `json:"acr"`
	PrefName       string                 `json:"preferred_username"`
	RealmAccess    RealmRoles             `json:"realm_access"`
	Groups         []string               `json:"groups"`
	ResourceAccess map[string]interface{} `json:"resource_access"`
	FamilyName     string                 `json:"family_name"`
	GivenName      string                 `json:"given_name"`
	Username       string                 `json:"username"`
	Authorization  Permissions            `json:"authorization"`
}

// isExpired checks if the token has expired.
func (r *UserContext) IsExpired() bool {
	return r.ExpiresAt.Before(time.Now())
}

// String returns a string representation of the user context.
func (r *UserContext) String() string {
	return fmt.Sprintf(
		"user: %s, expires: %s, roles: %s",
		r.PreferredName,
		r.ExpiresAt.String(),
		strings.Join(r.Roles, ","),
	)
}

// userContext holds the information extracted the token.
type UserContext struct {
	// the id of the user
	ID string
	// the audience for the token
	Audiences []string
	// whether the context is from a session cookie or authorization header
	BearerToken bool
	// the email associated to the user
	Email string
	// current level of authentication for user
	Acr string
	// the expiration of the access token
	ExpiresAt time.Time
	// groups is a collection of groups where user is member
	Groups []string
	// a name of the user
	Name string
	// preferredName is the name of the user
	PreferredName string
	// roles is a collection of roles the users holds
	Roles []string
	// rawToken
	RawToken string
	// claims
	Claims map[string]interface{}
	// permissions
	Permissions Permissions
}
