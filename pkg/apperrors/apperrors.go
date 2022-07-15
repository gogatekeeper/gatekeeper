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
	ErrSessionNotFound                 = errors.New("authentication session not found")
	ErrNoSessionStateFound             = errors.New("no session state found")
	ErrZeroLengthToken                 = errors.New("token has zero length")
	ErrInvalidSession                  = errors.New("invalid session identifier")
	ErrRefreshTokenExpired             = errors.New("the refresh token has expired")
	ErrDecryption                      = errors.New("failed to decrypt token")
)
