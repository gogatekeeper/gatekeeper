package models

import "go.uber.org/zap"

// RequestScope is a request level context scope passed between middleware.
type RequestScope struct {
	Identity     *UserContext
	Logger       *zap.Logger
	Path         string
	RawPath      string
	AccessDenied bool
	NoProxy      bool
}
