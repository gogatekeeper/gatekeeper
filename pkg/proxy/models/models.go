package models

import "go.uber.org/zap"

// RequestScope is a request level context scope passed between middleware.
type RequestScope struct {
	// AccessDenied indicates the request should not be proxied because of authentication failure/other failure
	AccessDenied bool
	// NoProxy indicates that request should not be proxied because it is endpoint which should not be proxied
	NoProxy bool
	// Identity is the user Identity of the request
	Identity *UserContext
	// The parsed (unescaped) value of the request path
	Path string
	// Preserve the original request path: KEYCLOAK-10864, KEYCLOAK-11276, KEYCLOAK-13315
	// The exact path received in the request, if different than Path
	RawPath string
	Logger  *zap.Logger
}
