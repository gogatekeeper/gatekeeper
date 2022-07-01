package apperrors

import (
	"errors"
)

var (
	ErrPermissionNotInToken            = errors.New("permissions missing in token")
	ErrResourceRetrieve                = errors.New("problem getting resources from IDP")
	ErrTokenScopeNotMatchResourceScope = errors.New("scopes in token doesn't match scopes in IDP resource")
	ErrNoIDPResourceForPath            = errors.New("could not find resource matching path")
	ErrResourceIDNotPresent            = errors.New("resource id not present in token permissions")
	ErrNoAuthzFound                    = errors.New("no authz found")
)
