package authorization

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/Nerzal/gocloak/v11"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
)

type Permission struct {
	Scopes       []string `json:"scopes"`
	ResourceID   string   `json:"rsid"`
	ResourceName string   `json:"rsname"`
}

type Permissions struct {
	Permissions []Permission `json:"permissions"`
}

type AuthzDecision int

const (
	UndefinedAuthz AuthzDecision = iota
	AllowedAuthz   AuthzDecision = iota
	DeniedAuthz    AuthzDecision = iota
)

func (decision AuthzDecision) String() string {
	switch decision {
	case AllowedAuthz:
		return strconv.Itoa(int(AllowedAuthz))
	case DeniedAuthz:
		return strconv.Itoa(int(DeniedAuthz))
	case UndefinedAuthz:
		return ""
	}
	return strconv.Itoa(int(DeniedAuthz))
}

type Provider interface {
	Authorize(Permissions, *http.Request, gocloak.GoCloak, time.Duration, string, string) (AuthzDecision, error)
}

var _ Provider = (*KeycloakAuthorizationProvider)(nil)

type KeycloakAuthorizationProvider struct{}

func (p *KeycloakAuthorizationProvider) Authorize(
	perms Permissions,
	req *http.Request,
	idpClient gocloak.GoCloak,
	idpTimeout time.Duration,
	PAT string,
	realm string,
) (AuthzDecision, error) {
	if len(perms.Permissions) == 0 {
		return DeniedAuthz, apperrors.ErrPermissionNotInToken
	}

	resctx, cancel := context.WithTimeout(
		context.Background(),
		idpTimeout,
	)

	defer cancel()

	matchingURI := true

	resourceParam := gocloak.GetResourceParams{
		URI:         &req.URL.Path,
		MatchingURI: &matchingURI,
	}

	resources, err := idpClient.GetResourcesClient(
		resctx,
		PAT,
		realm,
		resourceParam,
	)

	if err != nil {
		return DeniedAuthz, apperrors.ErrResourceRetrieve
	}

	if len(resources) == 0 {
		return DeniedAuthz, apperrors.ErrNoIDPResourceForPath
	}

	resourceID := resources[0].ID

	if *resourceID != perms.Permissions[0].ResourceID {
		return DeniedAuthz, apperrors.ErrResourceIDNotPresent
	}

	inter := make([]bool, 0)
	permScopes := make(map[string]bool)

	for _, scope := range *resources[0].ResourceScopes {
		permScopes[*scope.Name] = true
	}

	for _, scope := range perms.Permissions[0].Scopes {
		if permScopes[scope] {
			inter = append(inter, true)
		}
	}

	if len(inter) == 0 {
		return DeniedAuthz, apperrors.ErrTokenScopeNotMatchResourceScope
	}

	return AllowedAuthz, nil
}
