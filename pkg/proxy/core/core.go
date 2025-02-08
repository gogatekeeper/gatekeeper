package core

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type (
	KeycloakProvider string
	GoogleProvider   string
)

//nolint:gochecknoglobals
var (
	release  = ""
	gitsha   = "no gitsha provided"
	compiled = "0"
	Version  = ""
)

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
	Run() (context.Context, error)
	Shutdown() error
}

type ReverseProxy interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request)
}
