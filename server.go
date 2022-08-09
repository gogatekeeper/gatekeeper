/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap/zapcore"
	"gopkg.in/square/go-jose.v2/jwt"

	"golang.org/x/crypto/acme/autocert"

	httplog "log"

	"github.com/Nerzal/gocloak/v11"
	proxyproto "github.com/armon/go-proxyproto"
	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/elazarl/goproxy"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/storage"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"go.uber.org/zap"
)

type PAT struct {
	Token *gocloak.JWT
	m     sync.Mutex
}

type oauthProxy struct {
	provider       *oidc3.Provider
	config         *Config
	endpoint       *url.URL
	idpClient      gocloak.GoCloak
	listener       net.Listener
	log            *zap.Logger
	metricsHandler http.Handler
	router         http.Handler
	adminRouter    http.Handler
	server         *http.Server
	store          storage.Storage
	templates      *template.Template
	upstream       reverseProxy
	pat            *PAT
}

func init() {
	_, _ = time.LoadLocation("UTC")      // ensure all time is in UTC [NOTE(fredbi): no this does just nothing]
	runtime.GOMAXPROCS(runtime.NumCPU()) // set the core
	prometheus.MustRegister(certificateRotationMetric)
	prometheus.MustRegister(latencyMetric)
	prometheus.MustRegister(oauthLatencyMetric)
	prometheus.MustRegister(oauthTokensMetric)
	prometheus.MustRegister(statusMetric)
}

const allPath = "/*"

// newProxy create's a new proxy from configuration
//nolint:cyclop
func newProxy(config *Config) (*oauthProxy, error) {
	// create the service logger
	log, err := createLogger(config)

	if err != nil {
		return nil, err
	}

	err = config.update()

	if err != nil {
		return nil, err
	}

	log.Info(
		"starting the service",
		zap.String("prog", constant.Prog),
		zap.String("author", constant.Author),
		zap.String("version", version),
	)

	svc := &oauthProxy{
		config:         config,
		log:            log,
		metricsHandler: promhttp.Handler(),
	}

	// parse the upstream endpoint
	if svc.endpoint, err = url.Parse(config.Upstream); err != nil {
		return nil, err
	}

	// initialize the store if any
	if config.StoreURL != "" {
		if svc.store, err = storage.CreateStorage(config.StoreURL); err != nil {
			return nil, err
		}
	}

	svc.log.Info(
		"attempting to retrieve configuration discovery url",
		zap.String("url", svc.config.DiscoveryURL),
		zap.String("timeout", svc.config.OpenIDProviderTimeout.String()),
	)

	// initialize the openid client
	if svc.provider, svc.idpClient, err = svc.newOpenIDProvider(); err != nil {
		svc.log.Error(
			"failed to get provider configuration from discovery",
			zap.Error(err),
		)
		return nil, err
	}

	svc.log.Info("successfully retrieved openid configuration from the discovery")

	if config.EnableUma || config.EnableForwarding {
		patDone := make(chan bool)
		go svc.getPAT(patDone)
		<-patDone
	}

	if config.SkipTokenVerification {
		log.Warn(
			"TESTING ONLY CONFIG - access token verification has been disabled",
		)
	}

	if config.ClientID == "" && config.ClientSecret == "" {
		log.Warn(
			"client credentials are not set, depending on " +
				"provider (confidential|public) you might be unable to auth",
		)
	}

	// are we running in forwarding mode?
	if config.EnableForwarding {
		if err := svc.createForwardingProxy(); err != nil {
			return nil, err
		}
	} else {
		if err := svc.createReverseProxy(); err != nil {
			return nil, err
		}
	}

	return svc, nil
}

// createLogger is responsible for creating the service logger
func createLogger(config *Config) (*zap.Logger, error) {
	httplog.SetOutput(ioutil.Discard) // disable the http logger

	if config.DisableAllLogging {
		return zap.NewNop(), nil
	}

	cfg := zap.NewProductionConfig()
	cfg.DisableStacktrace = true
	cfg.DisableCaller = true

	// Use human-readable timestamps in the logs until KEYCLOAK-12100 is fixed
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	// are we enabling json logging?
	if !config.EnableJSONLogging {
		cfg.Encoding = "console"
	}

	// are we running verbose mode?
	if config.Verbose {
		httplog.SetOutput(os.Stderr)
		cfg.DisableCaller = false
		cfg.Development = true
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}

	return cfg.Build()
}

// useDefaultStack sets the default middleware stack for router
func (r *oauthProxy) useDefaultStack(engine chi.Router) {
	engine.NotFound(emptyHandler)

	if r.config.EnableDefaultDeny || r.config.EnableDefaultDenyStrict {
		engine.Use(r.methodCheckMiddleware)
	} else {
		engine.MethodNotAllowed(emptyHandler)
	}

	engine.Use(middleware.Recoverer)

	// @check if the request tracking id middleware is enabled
	if r.config.EnableRequestID {
		r.log.Info("enabled the correlation request id middleware")
		engine.Use(r.requestIDMiddleware(r.config.RequestIDHeader))
	}

	if r.config.EnableCompression {
		engine.Use(middleware.Compress(5))
	}

	// @step: enable the entrypoint middleware
	engine.Use(r.entrypointMiddleware)

	if r.config.EnableLogging {
		engine.Use(r.loggingMiddleware)
	}

	if r.config.EnableSecurityFilter {
		engine.Use(r.securityMiddleware)
	}
}

// createReverseProxy creates a reverse proxy
//nolint:cyclop
func (r *oauthProxy) createReverseProxy() error {
	r.log.Info(
		"enabled reverse proxy mode, upstream url",
		zap.String("url", r.config.Upstream),
	)

	if err := r.createUpstreamProxy(r.endpoint); err != nil {
		return err
	}

	engine := chi.NewRouter()
	r.useDefaultStack(engine)

	// @step: configure CORS middleware
	if len(r.config.CorsOrigins) > 0 {
		corsHandler := cors.New(cors.Options{
			AllowedOrigins:   r.config.CorsOrigins,
			AllowedMethods:   r.config.CorsMethods,
			AllowedHeaders:   r.config.CorsHeaders,
			AllowCredentials: r.config.CorsCredentials,
			ExposedHeaders:   r.config.CorsExposedHeaders,
			MaxAge:           int(r.config.CorsMaxAge.Seconds()),
			Debug:            r.config.Verbose,
		})

		engine.Use(corsHandler.Handler)
	}

	engine.Use(r.proxyMiddleware)
	r.router = engine

	if len(r.config.ResponseHeaders) > 0 {
		engine.Use(r.responseHeaderMiddleware(r.config.ResponseHeaders))
	}

	// step: define admin subrouter: health and metrics
	adminEngine := chi.NewRouter()

	r.log.Info(
		"enabled health service",
		zap.String("path", path.Clean(r.config.WithOAuthURI(constant.HealthURL))),
	)

	adminEngine.Get(constant.HealthURL, r.healthHandler)

	if r.config.EnableMetrics {
		r.log.Info(
			"enabled the service metrics middleware",
			zap.String("path", path.Clean(r.config.WithOAuthURI(constant.MetricsURL))),
		)
		adminEngine.Get(constant.MetricsURL, r.proxyMetricsHandler)
	}

	// step: add the routing for oauth
	engine.With(r.proxyDenyMiddleware).Route(r.config.BaseURI+r.config.OAuthURI, func(eng chi.Router) {
		eng.MethodNotAllowed(methodNotAllowHandlder)
		eng.HandleFunc(constant.AuthorizationURL, r.oauthAuthorizationHandler)
		eng.Get(constant.CallbackURL, r.oauthCallbackHandler)
		eng.Get(constant.ExpiredURL, r.expirationHandler)
		eng.With(r.authenticationMiddleware()).Get(constant.LogoutURL, r.logoutHandler)
		eng.With(r.authenticationMiddleware()).Get(constant.TokenURL, r.tokenHandler)
		eng.Post(constant.LoginURL, r.loginHandler)
		eng.Get(constant.DiscoveryURL, r.discoveryHandler)

		if r.config.ListenAdmin == "" {
			eng.Mount("/", adminEngine)
		}

		eng.NotFound(http.NotFound)
	})

	// step: define profiling subrouter
	var debugEngine chi.Router

	if r.config.EnableProfiling {
		r.log.Warn("enabling the debug profiling on " + constant.DebugURL)

		debugEngine = chi.NewRouter()
		debugEngine.Get("/{name}", r.debugHandler)
		debugEngine.Post("/{name}", r.debugHandler)

		// @check if the server write-timeout is still set and throw a warning
		if r.config.ServerWriteTimeout > 0 {
			r.log.Warn(
				"you should disable the server write timeout ( " +
					"--server-write-timeout) when using pprof profiling",
			)
		}

		if r.config.ListenAdmin == "" {
			engine.With(r.proxyDenyMiddleware).Mount(constant.DebugURL, debugEngine)
		}
	}

	if r.config.ListenAdmin != "" {
		// mount admin and debug engines separately
		r.log.Info("mounting admin endpoints on separate listener")

		admin := chi.NewRouter()
		admin.MethodNotAllowed(emptyHandler)
		admin.NotFound(emptyHandler)
		admin.Use(middleware.Recoverer)
		admin.Use(r.proxyDenyMiddleware)
		admin.Route("/", func(e chi.Router) {
			e.Mount(r.config.OAuthURI, adminEngine)
			if debugEngine != nil {
				e.Mount(constant.DebugURL, debugEngine)
			}
		})

		r.adminRouter = admin
	}

	if r.config.EnableSessionCookies {
		r.log.Info("using session cookies only for access and refresh tokens")
	}

	// step: load the templates if any
	if err := r.createTemplates(); err != nil {
		return err
	}

	// step: add custom http methods
	if r.config.CustomHTTPMethods != nil {
		for _, customHTTPMethod := range r.config.CustomHTTPMethods {
			chi.RegisterMethod(customHTTPMethod)
			utils.AllHTTPMethods = append(utils.AllHTTPMethods, customHTTPMethod)
		}
	}

	// step: provision in the protected resources
	enableDefaultDeny := r.config.EnableDefaultDeny
	enableDefaultDenyStrict := r.config.EnableDefaultDenyStrict

	for _, res := range r.config.Resources {
		if res.URL[len(res.URL)-1:] == "/" {
			r.log.Warn("the resource url is not a prefix",
				zap.String("resource", res.URL),
				zap.String("change", res.URL),
				zap.String("amended", strings.TrimRight(res.URL, "/")))
		}

		if res.URL == allPath && (r.config.EnableDefaultDeny || r.config.EnableDefaultDenyStrict) {
			switch res.WhiteListed {
			case true:
				return errors.New("you've asked for a default denial but whitelisted everything")
			default:
				enableDefaultDeny = false
				enableDefaultDenyStrict = false
			}
		}
	}

	if enableDefaultDeny || enableDefaultDenyStrict {
		r.log.Info("adding a default denial into the protected resources")

		r.config.Resources = append(
			r.config.Resources,
			&Resource{URL: allPath, Methods: utils.AllHTTPMethods},
		)
	}

	for _, res := range r.config.Resources {
		r.log.Info(
			"protecting resource",
			zap.String("resource", res.String()),
		)

		middlewares := []func(http.Handler) http.Handler{
			r.authenticationMiddleware(),
			r.admissionMiddleware(res),
			r.identityHeadersMiddleware(r.config.AddClaims),
		}

		if res.URL == allPath && !res.WhiteListed && enableDefaultDenyStrict {
			middlewares = []func(http.Handler) http.Handler{
				r.denyMiddleware,
				r.proxyDenyMiddleware,
			}
		}

		if r.config.EnableUma {
			middlewares = []func(http.Handler) http.Handler{
				r.authenticationMiddleware(),
				r.authorizationMiddleware(),
				r.admissionMiddleware(res),
				r.identityHeadersMiddleware(r.config.AddClaims),
			}
		}

		e := engine.With(middlewares...)

		for _, method := range res.Methods {
			if !res.WhiteListed {
				e.MethodFunc(method, res.URL, emptyHandler)
				continue
			}

			engine.MethodFunc(method, res.URL, emptyHandler)
		}
	}

	for name, value := range r.config.MatchClaims {
		r.log.Info(
			"token must contain",
			zap.String("claim", name),
			zap.String("value", value),
		)
	}

	if r.config.RedirectionURL == "" {
		r.log.Warn("no redirection url has been set, will use host headers")
	}

	if r.config.EnableEncryptedToken {
		r.log.Info("session access tokens will be encrypted")
	}

	return nil
}

// createForwardingProxy creates a forwarding proxy
func (r *oauthProxy) createForwardingProxy() error {
	r.log.Info(
		"enabling forward signing mode, listening on",
		zap.String("interface", r.config.Listen),
	)

	if r.config.SkipUpstreamTLSVerify {
		r.log.Warn(
			"tls verification switched off. In forward signing mode it's " +
				"recommended you verify! (--skip-upstream-tls-verify=false)",
		)
	}

	if err := r.createUpstreamProxy(nil); err != nil {
		return err
	}
	//nolint:bodyclose
	forwardingHandler := r.forwardProxyHandler()

	// set the http handler
	proxy, assertOk := r.upstream.(*goproxy.ProxyHttpServer)

	if !assertOk {
		return fmt.Errorf("assertion failed")
	}

	r.router = proxy

	// setup the tls configuration
	if r.config.TLSCaCertificate != "" && r.config.TLSCaPrivateKey != "" {
		cAuthority, err := utils.LoadCA(r.config.TLSCaCertificate, r.config.TLSCaPrivateKey)

		if err != nil {
			return fmt.Errorf("unable to load certificate authority, error: %s", err)
		}

		// implement the goproxy connect method
		proxy.OnRequest().HandleConnectFunc(
			func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				return &goproxy.ConnectAction{
					Action:    goproxy.ConnectMitm,
					TLSConfig: goproxy.TLSConfigFromCA(cAuthority),
				}, host
			},
		)
	} else {
		// use the default certificate provided by goproxy
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	}

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		// @NOTES, somewhat annoying but goproxy hands back a nil response on proxy client errors
		if resp != nil && r.config.EnableLogging {
			start, assertOk := ctx.UserData.(time.Time)

			if !assertOk {
				r.log.Error("assertion failed")
				return nil
			}

			latency := time.Since(start)
			latencyMetric.Observe(latency.Seconds())

			r.log.Info("client request",
				zap.String("method", resp.Request.Method),
				zap.String("path", resp.Request.URL.Path),
				zap.Int("status", resp.StatusCode),
				zap.Int64("bytes", resp.ContentLength),
				zap.String("host", resp.Request.Host),
				zap.String("path", resp.Request.URL.Path),
				zap.String("latency", latency.String()))
		}

		return resp
	})
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.UserData = time.Now()
		forwardingHandler(req, ctx.Resp)
		return req, ctx.Resp
	})

	return nil
}

// Run starts the proxy service
//nolint:cyclop
func (r *oauthProxy) Run() error {
	listener, err := r.createHTTPListener(makeListenerConfig(r.config))

	if err != nil {
		return err
	}

	// step: create the main http(s) server
	server := &http.Server{
		Addr:         r.config.Listen,
		Handler:      r.router,
		ReadTimeout:  r.config.ServerReadTimeout,
		WriteTimeout: r.config.ServerWriteTimeout,
		IdleTimeout:  r.config.ServerIdleTimeout,
	}

	r.server = server
	r.listener = listener

	go func() {
		r.log.Info(
			"Gatekeeper proxy service starting",
			zap.String("interface", r.config.Listen),
		)

		if err = server.Serve(listener); err != nil {
			if err != http.ErrServerClosed {
				r.log.Fatal("failed to start the http service", zap.Error(err))
			}
		}
	}()

	// step: are we running http service as well?
	if r.config.ListenHTTP != "" {
		r.log.Info(
			"Gatekeeper proxy http service starting",
			zap.String("interface", r.config.ListenHTTP),
		)

		httpListener, err := r.createHTTPListener(listenerConfig{
			listen:        r.config.ListenHTTP,
			proxyProtocol: r.config.EnableProxyProtocol,
		})

		if err != nil {
			return err
		}

		httpsvc := &http.Server{
			Addr:         r.config.ListenHTTP,
			Handler:      r.router,
			ReadTimeout:  r.config.ServerReadTimeout,
			WriteTimeout: r.config.ServerWriteTimeout,
			IdleTimeout:  r.config.ServerIdleTimeout,
		}

		go func() {
			if err := httpsvc.Serve(httpListener); err != nil {
				r.log.Fatal("failed to start the http redirect service", zap.Error(err))
			}
		}()
	}

	// step: are we running specific admin service as well?
	// if not, admin endpoints are added as routes in the main service
	if r.config.ListenAdmin != "" {
		r.log.Info(
			"keycloak proxy admin service starting",
			zap.String("interface", r.config.ListenAdmin),
		)

		var (
			adminListener net.Listener
			err           error
		)

		if r.config.ListenAdminScheme == constant.UnsecureScheme {
			// run the admin endpoint (metrics, health) with http
			adminListener, err = r.createHTTPListener(listenerConfig{
				listen:        r.config.ListenAdmin,
				proxyProtocol: r.config.EnableProxyProtocol,
			})

			if err != nil {
				return err
			}
		} else {
			adminListenerConfig := makeListenerConfig(r.config)
			// admin specific overides
			adminListenerConfig.listen = r.config.ListenAdmin

			// TLS configuration defaults to the one for the main service,
			// and may be overidden
			if r.config.TLSAdminPrivateKey != "" && r.config.TLSAdminCertificate != "" {
				adminListenerConfig.useFileTLS = true
				adminListenerConfig.certificate = r.config.TLSAdminCertificate
				adminListenerConfig.privateKey = r.config.TLSAdminPrivateKey
			}

			if r.config.TLSAdminCaCertificate != "" {
				adminListenerConfig.ca = r.config.TLSAdminCaCertificate
			}

			if r.config.TLSAdminClientCertificate != "" {
				adminListenerConfig.clientCert = r.config.TLSAdminClientCertificate
			}

			adminListener, err = r.createHTTPListener(adminListenerConfig)
			if err != nil {
				return err
			}
		}

		adminsvc := &http.Server{
			Addr:         r.config.ListenAdmin,
			Handler:      r.adminRouter,
			ReadTimeout:  r.config.ServerReadTimeout,
			WriteTimeout: r.config.ServerWriteTimeout,
			IdleTimeout:  r.config.ServerIdleTimeout,
		}

		go func() {
			if ers := adminsvc.Serve(adminListener); err != nil {
				r.log.Fatal("failed to start the admin service", zap.Error(ers))
			}
		}()
	}

	return nil
}

// listenerConfig encapsulate listener options
type listenerConfig struct {
	ca                  string   // the path to a certificate authority
	certificate         string   // the path to the certificate if any
	clientCert          string   // the path to a client certificate to use for mutual tls
	hostnames           []string // list of hostnames the service will respond to
	letsEncryptCacheDir string   // the path to cache letsencrypt certificates
	listen              string   // the interface to bind the listener to
	privateKey          string   // the path to the private key if any
	proxyProtocol       bool     // whether to enable proxy protocol on the listen
	redirectionURL      string   // url to redirect to
	useFileTLS          bool     // indicates we are using certificates from files
	useLetsEncryptTLS   bool     // indicates we are using letsencrypt
	useSelfSignedTLS    bool     // indicates we are using the self-signed tls
	minTLSVersion       uint16   // server minimal TLS version
}

// makeListenerConfig extracts a listener configuration from a proxy Config
func makeListenerConfig(config *Config) listenerConfig {
	var minTLSVersion uint16
	switch strings.ToLower(config.TLSMinVersion) {
	case "":
		minTLSVersion = 0 // zero means default value
	case "tlsv1.0":
		minTLSVersion = tls.VersionTLS10
	case "tlsv1.1":
		minTLSVersion = tls.VersionTLS11
	case "tlsv1.2":
		minTLSVersion = tls.VersionTLS12
	case "tlsv1.3":
		minTLSVersion = tls.VersionTLS13
	}

	return listenerConfig{
		hostnames:           config.Hostnames,
		letsEncryptCacheDir: config.LetsEncryptCacheDir,
		listen:              config.Listen,
		proxyProtocol:       config.EnableProxyProtocol,
		redirectionURL:      config.RedirectionURL,

		// TLS settings
		useFileTLS:        config.TLSPrivateKey != "" && config.TLSCertificate != "",
		privateKey:        config.TLSPrivateKey,
		ca:                config.TLSCaCertificate,
		certificate:       config.TLSCertificate,
		clientCert:        config.TLSClientCertificate,
		useLetsEncryptTLS: config.UseLetsEncrypt,
		useSelfSignedTLS:  config.EnabledSelfSignedTLS,
		minTLSVersion:     minTLSVersion,
	}
}

// ErrHostNotConfigured indicates the hostname was not configured
var ErrHostNotConfigured = errors.New("acme/autocert: host not configured")

// createHTTPListener is responsible for creating a listening socket
//nolint:cyclop
func (r *oauthProxy) createHTTPListener(config listenerConfig) (net.Listener, error) {
	var listener net.Listener
	var err error

	// are we create a unix socket or tcp listener?
	if strings.HasPrefix(config.listen, "unix://") {
		socket := config.listen[7:]

		if exists := utils.FileExists(socket); exists {
			if err = os.Remove(socket); err != nil {
				return nil, err
			}
		}

		r.log.Info(
			"listening on unix socket",
			zap.String("interface", config.listen),
		)

		if listener, err = net.Listen("unix", socket); err != nil {
			return nil, err
		}
	} else { //nolint:gocritic
		if listener, err = net.Listen("tcp", config.listen); err != nil {
			return nil, err
		}
	}

	// does it require proxy protocol?
	if config.proxyProtocol {
		r.log.Info(
			"enabling the proxy protocol on listener",
			zap.String("interface", config.listen),
		)
		listener = &proxyproto.Listener{Listener: listener}
	}

	// @check if the socket requires TLS
	if config.useSelfSignedTLS || config.useLetsEncryptTLS || config.useFileTLS {
		getCertificate := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, errors.New("not configured")
		}

		if config.useLetsEncryptTLS {
			r.log.Info("enabling letsencrypt tls support")

			manager := autocert.Manager{
				Prompt: autocert.AcceptTOS,
				Cache:  autocert.DirCache(config.letsEncryptCacheDir),
				HostPolicy: func(_ context.Context, host string) error {
					if len(config.hostnames) > 0 {
						found := false

						for _, h := range config.hostnames {
							found = found || (h == host)
						}

						if !found {
							return ErrHostNotConfigured
						}
					} else if config.redirectionURL != "" {
						if u, err := url.Parse(config.redirectionURL); err != nil {
							return err
						} else if u.Host != host {
							return ErrHostNotConfigured
						}
					}

					return nil
				},
			}

			getCertificate = manager.GetCertificate
		}

		if config.useSelfSignedTLS {
			r.log.Info(
				"enabling self-signed tls support",
				zap.Duration("expiration", r.config.SelfSignedTLSExpiration),
			)

			rotate, err := newSelfSignedCertificate(
				r.config.SelfSignedTLSHostnames,
				r.config.SelfSignedTLSExpiration,
				r.log,
			)

			if err != nil {
				return nil, err
			}

			getCertificate = rotate.GetCertificate
		}

		if config.useFileTLS {
			r.log.Info(
				"tls support enabled",
				zap.String("certificate", config.certificate),
				zap.String("private_key", config.privateKey),
			)

			rotate, err := newCertificateRotator(
				config.certificate,
				config.privateKey,
				r.log,
			)

			if err != nil {
				return nil, err
			}

			// start watching the files for changes
			if err := rotate.watch(); err != nil {
				return nil, err
			}

			getCertificate = rotate.GetCertificate
		}

		tlsConfig := &tls.Config{
			GetCertificate: getCertificate,
			// Causes servers to use Go's default ciphersuite preferences,
			// which are tuned to avoid attacks. Does nothing on clients.
			PreferServerCipherSuites: true,
			NextProtos:               []string{"h2", "http/1.1"},
			MinVersion:               config.minTLSVersion,
		}

		listener = tls.NewListener(listener, tlsConfig)

		// @check if we doing mutual tls
		if config.clientCert != "" {
			caCert, err := ioutil.ReadFile(config.clientCert)

			if err != nil {
				return nil, err
			}

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	return listener, nil
}

// createUpstreamProxy create a reverse http proxy from the upstream
func (r *oauthProxy) createUpstreamProxy(upstream *url.URL) error {
	dialer := (&net.Dialer{
		KeepAlive: r.config.UpstreamKeepaliveTimeout,
		Timeout:   r.config.UpstreamTimeout,
	}).Dial

	// are we using a unix socket?
	if upstream != nil && upstream.Scheme == "unix" {
		r.log.Info(
			"using unix socket for upstream",
			zap.String("socket", fmt.Sprintf("%s%s", upstream.Host, upstream.Path)),
		)

		socketPath := fmt.Sprintf("%s%s", upstream.Host, upstream.Path)
		dialer = func(network, address string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		}

		upstream.Path = ""
		upstream.Host = "domain-sock"
		upstream.Scheme = constant.UnsecureScheme
	}
	// create the upstream tls configure
	//nolint:gas
	tlsConfig := &tls.Config{InsecureSkipVerify: r.config.SkipUpstreamTLSVerify}

	// are we using a client certificate
	// @TODO provide a means of reload on the client certificate when it expires. I'm not sure if it's just a
	// case of update the http transport settings - Also we to place this go-routine?
	if r.config.TLSClientCertificate != "" {
		cert, err := ioutil.ReadFile(r.config.TLSClientCertificate)

		if err != nil {
			r.log.Error(
				"unable to read client certificate",
				zap.String("path", r.config.TLSClientCertificate),
				zap.Error(err),
			)
			return err
		}

		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(cert)
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	{
		// @check if we have a upstream ca to verify the upstream
		if r.config.UpstreamCA != "" {
			r.log.Info(
				"loading the upstream ca",
				zap.String("path", r.config.UpstreamCA),
			)

			cAuthority, err := ioutil.ReadFile(r.config.UpstreamCA)

			if err != nil {
				return err
			}

			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(cAuthority)
			tlsConfig.RootCAs = pool
		}
	}

	// create the forwarding proxy
	proxy := goproxy.NewProxyHttpServer()

	// headers formed by middleware before proxying to upstream shall be
	// kept in response. This is true for CORS headers ([KEYCOAK-9045])
	// and for refreshed cookies (htts://github.com/louketo/louketo-proxy/pulls/456])
	proxy.KeepDestinationHeaders = true
	proxy.Logger = httplog.New(ioutil.Discard, "", 0)
	proxy.KeepDestinationHeaders = true
	r.upstream = proxy

	// update the tls configuration of the reverse proxy
	upstreamProxy, assertOk := r.upstream.(*goproxy.ProxyHttpServer)

	if !assertOk {
		return fmt.Errorf("assertion failed")
	}

	upstreamProxy.Tr = &http.Transport{
		Dial:                  dialer,
		DisableKeepAlives:     !r.config.UpstreamKeepalives,
		ExpectContinueTimeout: r.config.UpstreamExpectContinueTimeout,
		ResponseHeaderTimeout: r.config.UpstreamResponseHeaderTimeout,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   r.config.UpstreamTLSHandshakeTimeout,
		MaxIdleConns:          r.config.MaxIdleConns,
		MaxIdleConnsPerHost:   r.config.MaxIdleConnsPerHost,
	}

	return nil
}

// createTemplates loads the custom template
func (r *oauthProxy) createTemplates() error {
	var list []string

	if r.config.SignInPage != "" {
		r.log.Debug(
			"loading the custom sign in page",
			zap.String("page", r.config.SignInPage),
		)

		list = append(list, r.config.SignInPage)
	}

	if r.config.ForbiddenPage != "" {
		r.log.Debug(
			"loading the custom sign forbidden page",
			zap.String("page", r.config.ForbiddenPage),
		)

		list = append(list, r.config.ForbiddenPage)
	}

	if r.config.ErrorPage != "" {
		r.log.Debug(
			"loading the custom error page",
			zap.String("page", r.config.ErrorPage),
		)

		list = append(list, r.config.ErrorPage)
	}

	if len(list) > 0 {
		r.log.Info(
			"loading the custom templates",
			zap.String("templates", strings.Join(list, ",")),
		)

		r.templates = template.Must(template.ParseFiles(list...))
	}

	return nil
}

// newOpenIDProvider initializes the openID configuration, note: the redirection url is deliberately left blank
// in order to retrieve it from the host header on request
func (r *oauthProxy) newOpenIDProvider() (*oidc3.Provider, gocloak.GoCloak, error) {
	host := fmt.Sprintf(
		"%s://%s",
		r.config.DiscoveryURI.Scheme,
		r.config.DiscoveryURI.Host,
	)
	client := gocloak.NewClient(host)
	restyClient := client.RestyClient()
	restyClient.SetDebug(r.config.Verbose)
	restyClient.SetTimeout(r.config.OpenIDProviderTimeout)
	restyClient.SetTLSClientConfig(
		&tls.Config{
			InsecureSkipVerify: r.config.SkipOpenIDProviderTLSVerify,
		},
	)

	if r.config.OpenIDProviderProxy != "" {
		restyClient.SetProxy(r.config.OpenIDProviderProxy)
	}

	// see https://github.com/coreos/go-oidc/issues/214
	// see https://github.com/coreos/go-oidc/pull/260
	ctx := oidc3.ClientContext(context.Background(), restyClient.GetClient())
	provider, err := oidc3.NewProvider(ctx, r.config.DiscoveryURL)

	if err != nil {
		return nil,
			nil,
			fmt.Errorf(
				"failed to retrieve the provider configuration from discovery url: %w",
				err,
			)
	}

	return provider, client, nil
}

// Render implements the echo Render interface
func (r *oauthProxy) Render(w io.Writer, name string, data interface{}) error {
	return r.templates.ExecuteTemplate(w, name, data)
}

//nolint:cyclop
func (r *oauthProxy) getPAT(done chan bool) {
	retry := 0
	r.pat = &PAT{}
	initialized := false
	config := *r.config
	clientID := config.ClientID
	clientSecret := config.ClientSecret
	realm := config.Realm
	timeout := config.OpenIDProviderTimeout
	patRetryCount := config.PatRetryCount
	patRetryInterval := config.PatRetryInterval
	grantType := GrantTypeClientCreds

	if config.EnableForwarding && config.ForwardingGrantType == GrantTypeUserCreds {
		grantType = GrantTypeUserCreds
	}

	for {
		if retry > 0 {
			r.log.Info(
				"retrying fetching PAT token",
				zap.Int("retry", retry),
			)
		}

		ctx, cancel := context.WithTimeout(
			context.Background(),
			timeout,
		)

		var token *gocloak.JWT
		var err error

		switch grantType {
		case GrantTypeClientCreds:
			token, err = r.idpClient.LoginClient(
				ctx,
				clientID,
				clientSecret,
				realm,
			)
		case GrantTypeUserCreds:
			token, err = r.idpClient.Login(
				ctx,
				clientID,
				clientSecret,
				realm,
				config.ForwardingUsername,
				config.ForwardingPassword,
			)
		default:
			r.log.Error(
				"Chosen grant type is not supported",
				zap.String("grant_type", grantType),
			)
			os.Exit(11)
		}

		if err != nil {
			retry++
			r.log.Error(
				"problem getting PAT token",

				zap.Error(err),
			)

			if retry >= patRetryCount {
				cancel()
				os.Exit(10)
			}

			<-time.After(patRetryInterval)
			continue
		}

		r.pat.m.Lock()
		r.pat.Token = token
		r.pat.m.Unlock()

		if !initialized {
			done <- true
		}

		initialized = true

		parsedToken, err := jwt.ParseSigned(token.AccessToken)

		if err != nil {
			retry++
			r.log.Error("failed to parse the access token", zap.Error(err))
			<-time.After(patRetryInterval)
			continue
		}

		stdClaims := &jwt.Claims{}

		err = parsedToken.UnsafeClaimsWithoutVerification(stdClaims)

		if err != nil {
			retry++
			r.log.Error("unable to parse access token for claims", zap.Error(err))
			<-time.After(patRetryInterval)
			continue
		}

		retry = 0
		expiration := stdClaims.Expiry.Time()

		refreshIn := utils.GetWithin(expiration, 0.85)

		r.log.Info(
			"waiting for expiration of access token",
			zap.Float64("refresh_in", refreshIn.Seconds()),
		)

		<-time.After(refreshIn)
	}
}
