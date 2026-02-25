package models

import (
	"fmt"
	"strings"
	"time"
)

type Permission struct {
	ResourceID   string   `json:"rsid"`
	ResourceName string   `json:"rsname"`
	Scopes       []string `json:"scopes"`
}

type Permissions struct {
	Permissions []Permission `json:"permissions"`
}

type RealmRoles struct {
	Roles []string `json:"roles"`
}

type CustClaims struct {
	Email          string         `json:"email"`
	Acr            string         `json:"acr"`
	PrefName       string         `json:"preferred_username"`
	RealmAccess    RealmRoles     `json:"realm_access"`
	Groups         []string       `json:"groups"`
	ResourceAccess map[string]any `json:"resource_access"`
	FamilyName     string         `json:"family_name"`
	GivenName      string         `json:"given_name"`
	Username       string         `json:"username"`
	Authorization  Permissions    `json:"authorization"`
}

// IsExpired checks if the token has expired.
func (r *UserContext) IsExpired() bool {
	return r.ExpiresAt.Before(time.Now())
}

func (r *UserContext) String() string {
	return fmt.Sprintf(
		"user: %s, expires: %s, roles: %s",
		r.PreferredName,
		r.ExpiresAt.String(),
		strings.Join(r.Roles, ","),
	)
}

// UserContext holds the information extracted the token.
type UserContext struct {
	ExpiresAt      time.Time
	UserInfoClaims map[string]any
	IDTokenClaims  map[string]any
	Claims         map[string]any
	RawToken       string
	Email          string
	Acr            string
	ID             string
	Name           string
	PreferredName  string
	Groups         []string
	Roles          []string
	Permissions    Permissions
	Audiences      []string
	BearerToken    bool
}
