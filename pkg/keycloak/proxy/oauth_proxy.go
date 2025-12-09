package proxy

import (
	"net"
	"net/http"
	"net/url"
	"sync"

	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	keycloak_client "github.com/gogatekeeper/gatekeeper/pkg/keycloak/client"
	"github.com/gogatekeeper/gatekeeper/pkg/keycloak/config"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/cookie"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/core"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/storage"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type PAT struct {
	Token *models.TokenResponse
	m     sync.RWMutex
}

type RPT struct {
	Token string
	m     sync.RWMutex
}

type OauthProxy struct {
	Provider       *oidc3.Provider
	Config         *config.Config
	Endpoint       *url.URL
	IdpClient      *keycloak_client.Client
	Listener       net.Listener
	Log            *zap.Logger
	metricsHandler http.Handler
	Router         http.Handler
	adminRouter    http.Handler
	Server         *http.Server
	HTTPServer     *http.Server
	AdminServer    *http.Server
	Store          storage.Storage
	Upstream       core.ReverseProxy
	pat            *PAT
	rpt            *RPT
	Cm             *cookie.Manager
	ErrGroup       *errgroup.Group
}
