package authorization

import (
	"context"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
)

var _ Provider = (*KeycloakAuthorizationProvider)(nil)

type KeycloakAuthorizationProvider struct {
	perms       models.Permissions
	targetPath  string
	idpClient   *gocloak.GoCloak
	idpTimeout  time.Duration
	pat         string
	realm       string
	methodScope *string
}

func NewKeycloakAuthorizationProvider(
	perms models.Permissions,
	targetPath string,
	idpClient *gocloak.GoCloak,
	idpTimeout time.Duration,
	pat string,
	realm string,
	methodScope *string,
) Provider {
	return &KeycloakAuthorizationProvider{
		perms:       perms,
		targetPath:  targetPath,
		idpClient:   idpClient,
		idpTimeout:  idpTimeout,
		pat:         pat,
		realm:       realm,
		methodScope: methodScope,
	}
}

func (p *KeycloakAuthorizationProvider) Authorize() (AuthzDecision, error) {
	if len(p.perms.Permissions) == 0 {
		return DeniedAuthz, apperrors.ErrPermissionNotInToken
	}

	resctx, cancel := context.WithTimeout(
		context.Background(),
		p.idpTimeout,
	)

	defer cancel()

	matchingURI := true
	resourceParam := gocloak.GetResourceParams{
		URI:         &p.targetPath,
		MatchingURI: &matchingURI,
		Scope:       p.methodScope,
	}

	resources, err := p.idpClient.GetResourcesClient(
		resctx,
		p.pat,
		p.realm,
		resourceParam,
	)

	if err != nil {
		return DeniedAuthz, apperrors.ErrResourceRetrieve
	}

	if len(resources) == 0 {
		return DeniedAuthz, apperrors.ErrNoIDPResourceForPath
	}

	resourceID := resources[0].ID

	if *resourceID != p.perms.Permissions[0].ResourceID {
		return DeniedAuthz, apperrors.ErrResourceIDNotPresent
	}

	inter := make([]bool, 0)
	permScopes := make(map[string]bool)

	for _, scope := range *resources[0].ResourceScopes {
		permScopes[*scope.Name] = true
	}

	for _, scope := range p.perms.Permissions[0].Scopes {
		if permScopes[scope] {
			inter = append(inter, true)
		}
	}

	if len(inter) == 0 {
		return DeniedAuthz, apperrors.ErrTokenScopeNotMatchResourceScope
	}

	return AllowedAuthz, nil
}

func (p *KeycloakAuthorizationProvider) GenerateUMATicket() (string, error) {
	resctx, cancel := context.WithTimeout(
		context.Background(),
		p.idpTimeout,
	)

	defer cancel()

	matchingURI := true
	resourceParam := gocloak.GetResourceParams{
		URI:         &p.targetPath,
		MatchingURI: &matchingURI,
		Scope:       p.methodScope,
	}

	resources, err := p.idpClient.GetResourcesClient(
		resctx,
		p.pat,
		p.realm,
		resourceParam,
	)
	if err != nil {
		return "", err
	}

	if len(resources) == 0 {
		return "", apperrors.ErrNoIDPResourceForPath
	}

	resourceID := resources[0].ID
	resourceScopes := make([]string, 0)

	if len(*resources[0].ResourceScopes) == 0 {
		return "", apperrors.ErrMissingScopesForResource
	}

	for _, scope := range *resources[0].ResourceScopes {
		resourceScopes = append(resourceScopes, *scope.Name)
	}

	permissions := []gocloak.CreatePermissionTicketParams{
		{
			ResourceID:     resourceID,
			ResourceScopes: &resourceScopes,
		},
	}

	permTicket, err := p.idpClient.CreatePermissionTicket(
		resctx,
		p.pat,
		p.realm,
		permissions,
	)
	if err != nil {
		return "", err
	}

	return *permTicket.Ticket, nil
}
