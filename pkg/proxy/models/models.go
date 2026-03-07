package models

import (
	"time"

	"go.uber.org/zap"
)

// RequestScope is a request level context scope passed between middleware.
type RequestScope struct {
	Identity                 *UserContext
	Logger                   *zap.Logger
	Path                     string
	RawPath                  string
	RefreshedAccessCookie    string
	RefreshedAccessExpiresIn time.Duration
	RefreshedUMACookie       string
	RefreshedUMAExpiresIn    time.Duration
	AccessDenied             bool
	NoProxy                  bool
}
