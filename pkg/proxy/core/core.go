package core

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type KeycloakProvider string
type GoogleProvider string

var (
	release  = ""
	gitsha   = "no gitsha provided"
	compiled = "0"
	Version  = ""
)

// GetVersion returns the proxy version
func GetVersion() string {
	if Version == "" {
		tm, err := strconv.ParseInt(compiled, 10, 64)
		if err != nil {
			return "unable to parse compiled time"
		}
		Version = fmt.Sprintf("%s (git+sha: %s, built: %s)", release, gitsha, time.Unix(tm, 0).Format("02-01-2006"))
	}

	return Version
}

type OauthProxies interface {
	CreateReverseProxy() error
	Run() error
	Shutdown() error
}

// ReverseProxy is a wrapper
type ReverseProxy interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request)
}
