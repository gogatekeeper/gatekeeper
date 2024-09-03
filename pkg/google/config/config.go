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

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/config/core"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"gopkg.in/yaml.v2"
)

// Config is the configuration for the proxy
type Config struct {
	// ConfigFile is the binding interface
	ConfigFile string `env:"CONFIG_FILE" json:"config" usage:"path the a configuration file" yaml:"config"`
	// Listen defines the binding interface for main listener, e.g. {address}:{port}. This is required and there is no default value.
	Listen string `env:"LISTEN" json:"listen" usage:"Defines the binding interface for main listener, e.g. {address}:{port}. This is required and there is no default value" yaml:"listen"`
	// ListenHTTP is the interface to bind the http only service on
	ListenHTTP string `env:"LISTEN_HTTP" json:"listen-http" usage:"interface we should be listening to for HTTP traffic" yaml:"listen-http"`
	// ListenAdmin defines the interface to bind admin-only endpoint (live-status, debug, prometheus...). If not defined, this defaults to the main listener defined by Listen.
	ListenAdmin string `env:"LISTEN_ADMIN" json:"listen-admin" usage:"defines the interface to bind admin-only endpoint (live-status, debug, prometheus...). If not defined, this defaults to the main listener defined by Listen" yaml:"listen-admin"`
	// ListenAdminScheme defines the scheme admin endpoints are served with. If not defined, same as main listener.
	ListenAdminScheme string `env:"LISTEN_ADMIN_SCHEME" json:"listen-admin-scheme" usage:"scheme to serve admin-only endpoint (http or https)." yaml:"listen-admin-scheme"`
	// DiscoveryURL is the url for the keycloak server
	DiscoveryURL string `env:"DISCOVERY_URL" json:"discovery-url" usage:"discovery url to retrieve the openid configuration" yaml:"discovery-url"`
	// ClientID is the client id
	ClientID string `env:"CLIENT_ID" json:"client-id" usage:"client id used to authenticate to the oauth service" yaml:"client-id"`
	// ClientSecret is the secret for AS
	ClientSecret string `env:"CLIENT_SECRET" json:"client-secret" usage:"client secret used to authenticate to the oauth service" yaml:"client-secret"`
	// RedirectionURL the redirection url
	RedirectionURL string `env:"REDIRECTION_URL" json:"redirection-url" usage:"redirection url for the oauth callback url, defaults to host header if absent" yaml:"redirection-url"`
	// PostLogoutRedirectUri the url to which is redirected after logout
	PostLogoutRedirectURI string `env:"POST_LOGOUT_REDIRECT_URI" json:"post-logout-redirect-uri" usage:"url to which client is redirected after successful logout" yaml:"post-logout-redirect-uri"`
	// RevocationEndpoint is the token revocation endpoint to revoke refresh tokens
	RevocationEndpoint string `env:"REVOCATION_URL" json:"revocation-url" usage:"url for the revocation endpoint to revoke refresh token" yaml:"revocation-url"`
	// SkipOpenIDProviderTLSVerify skips the tls verification for openid provider communication
	SkipOpenIDProviderTLSVerify bool `env:"SKIP_OPENID_PROVIDER_TLSVERIFY" json:"skip-openid-provider-tls-verify" usage:"skip the verification of any TLS communication with the openid provider" yaml:"skip-openid-provider-tls-verify"`
	// OpenIDProviderProxy proxy for openid provider communication
	OpenIDProviderProxy string `env:"OPENID_PROVIDER_PROXY" json:"openid-provider-proxy" usage:"proxy for communication with the openid provider" yaml:"openid-provider-proxy"`
	// OpenIDProviderTimeout is the timeout used to pulling the openid configuration from the provider
	OpenIDProviderTimeout time.Duration `env:"OPENID_PROVIDER_TIMEOUT" json:"openid-provider-timeout" usage:"timeout for openid configuration on .well-known/openid-configuration" yaml:"openid-provider-timeout"`
	// OpenIDProviderRetryCount
	OpenIDProviderRetryCount int `env:"OPENID_PROVIDER_RETRY_COUNT" json:"openid-provider-retry-count" usage:"number of retries for retrieving openid configuration" yaml:"openid-provider-retry-count"`
	// OpenIDProviderHeaders
	OpenIDProviderHeaders map[string]string `json:"openid-provider-headers" usage:"http headers sent to idp provider" yaml:"openid-provider-headers"`
	// BaseURI is prepended to all the generated URIs
	BaseURI string `env:"BASE_URI" json:"base-uri" usage:"common prefix for all URIs" yaml:"base-uri"`
	// OAuthURI is the uri for the oauth endpoints for the proxy
	OAuthURI string `env:"OAUTH_URI" json:"oauth-uri" usage:"the uri for proxy oauth endpoints" yaml:"oauth-uri"`
	// Scopes is a list of scope we should request
	Scopes []string `json:"scopes" usage:"list of scopes requested when authenticating the user" yaml:"scopes"`
	// Upstream is the upstream endpoint i.e whom were proxying to
	Upstream string `env:"UPSTREAM_URL" json:"upstream-url" usage:"url for the upstream endpoint you wish to proxy" yaml:"upstream-url"`
	// UpstreamCA is the path to a CA certificate in PEM format to validate the upstream certificate
	UpstreamCA string `env:"UPSTREAM_CA" json:"upstream-ca" usage:"the path to a file container a CA certificate to validate the upstream tls endpoint" yaml:"upstream-ca"`
	// Resources is a list of protected resources
	Resources []*authorization.Resource `json:"resources" usage:"list of resources 'uri=/admin*|methods=GET,PUT|roles=role1,role2'" yaml:"resources"`
	// Headers permits adding customs headers across the board
	Headers map[string]string `json:"headers" usage:"custom headers to the upstream request, key=value" yaml:"headers"`
	// PreserveHost preserves the host header of the proxied request in the upstream request
	PreserveHost bool `env:"PRESERVE_HOST" json:"preserve-host" usage:"preserve the host header of the proxied request in the upstream request" yaml:"preserve-host"`
	// RequestIDHeader is the header name for request ids
	RequestIDHeader string `env:"REQUEST_ID_HEADER" json:"request-id-header" usage:"the http header name for request id" yaml:"request-id-header"`
	// ResponseHeader is a map of response headers to add to the response
	ResponseHeaders map[string]string `json:"response-headers" usage:"custom headers to added to the http response key=value" yaml:"response-headers"`
	// CustomHTTPMethods is a list of additional non-standard http methods. If additional method is required it has to explicitly allowed at resource allowed method definition.
	CustomHTTPMethods []string `json:"custom-http-methods" usage:"list of additional non-standard http methods" yaml:"custom-http-methods"`
	// Allowed Query Params sent to IDP
	AllowedQueryParams map[string]string `json:"allowed-query-params" usage:"allowed query params, sent to IDP key=optional value" yaml:"allowed-query-params"`
	// Default Allowed Query Params
	DefaultAllowedQueryParams map[string]string `json:"default-allowed-query-params" usage:"default allowed query params, sent to IDP key=value" yaml:"default-allowed-query-params"`

	// EnableSelfSignedTLS indicates we should create a self-signed ceritificate for the service
	EnabledSelfSignedTLS bool `env:"ENABLE_SELF_SIGNED_TLS" json:"enable-self-signed-tls" usage:"create self signed certificates for the proxy" yaml:"enable-self-signed-tls"`
	// SelfSignedTLSHostnames is the list of hostnames to place on the certificate
	SelfSignedTLSHostnames []string `json:"self-signed-tls-hostnames" usage:"a list of hostnames to place on the self-signed certificate" yaml:"self-signed-tls-hostnames"`
	// SelfSignedTLSExpiration is the expiration time of the tls certificate before rotation occurs
	SelfSignedTLSExpiration time.Duration `env:"SELF_SIGNED_TLS_EXPIRATION" json:"self-signed-tls-expiration" usage:"the expiration of the certificate before rotation" yaml:"self-signed-tls-expiration"`

	// EnableRequestID indicates the proxy should add request id if none if found
	EnableRequestID bool `env:"ENABLE_REQUEST_ID" json:"enable-request-id" usage:"indicates we should add a request id if none found" yaml:"enable-request-id"`
	// EnableLogoutRedirect indicates we should redirect to the identity provider for logging out
	EnableLogoutRedirect bool `env:"ENABLE_LOGOUT_REDIRECT" json:"enable-logout-redirect" usage:"indicates we should redirect to the identity provider for logging out" yaml:"enable-logout-redirect"`
	// EnableDefaultDeny indicates we should deny by default all unauthenticated requests
	EnableDefaultDeny bool `env:"ENABLE_DEFAULT_DENY" json:"enable-default-deny" usage:"enables a default denial on all unauthenticated requests, you have to explicitly say what is permitted, although be aware that it allows any valid token" yaml:"enable-default-deny"`
	// EnableDefaultDenyStrict indicates we should deny by default all requests
	EnableDefaultDenyStrict bool `env:"ENABLE_DEFAULT_DENY_STRICT" json:"enable-default-deny-strict" usage:"enables a default denial on all requests, even valid token is denied unless you create some resources" yaml:"enable-default-deny-strict"`
	// EnableEncryptedToken indicates the access token should be encoded
	EnableEncryptedToken bool `env:"ENABLE_ENCRYPTED_TOKEN" json:"enable-encrypted-token" usage:"enable encryption for the access tokens" yaml:"enable-encrypted-token"`
	// ForceEncryptedCookie indicates that the access token in the cookie should be encoded, regardless what EnableEncryptedToken says. This way, Louketo Proxy may receive tokens in header in the clear, whereas tokens in cookies remain encrypted
	ForceEncryptedCookie bool `env:"FORCE_ENCRYPTED_COOKIE" json:"force-encrypted-cookie" usage:"force encryption for the access tokens in cookies" yaml:"force-encrypted-cookie"`
	// EnableLogging indicates if we should log all the requests
	EnableLogging bool `env:"ENABLE_LOGGING" json:"enable-logging" usage:"enable http logging of the requests" yaml:"enable-logging"`
	// EnableJSONLogging is the logging format
	EnableJSONLogging bool `env:"ENABLE_JSON_LOGGING" json:"enable-json-logging" usage:"switch on json logging rather than text" yaml:"enable-json-logging"`
	// EnableForwarding enables the forwarding proxy
	EnableForwarding bool `env:"ENABLE_FORWARDING" json:"enable-forwarding" usage:"enables the forwarding proxy mode, signing outbound request" yaml:"enable-forwarding"`
	// EnableSecurityFilter enabled the security handler
	EnableSecurityFilter bool `env:"ENABLE_SECURITY_FILTER" json:"enable-security-filter" usage:"enables the security filter handler" yaml:"enable-security-filter"`
	// EnableRefreshTokens indicate's you wish to ignore using refresh tokens and re-auth on expiration of access token
	EnableRefreshTokens bool `env:"ENABLE_REFRESH_TOKEN" json:"enable-refresh-tokens" usage:"enables the handling of the refresh tokens" yaml:"enable-refresh-tokens"`
	// EnableSessionCookies indicates the cookies, both token and refresh should not be persisted
	EnableSessionCookies bool `env:"ENABLE_SESSION_COOKIES" json:"enable-session-cookies" usage:"access and refresh tokens are session only i.e. removed browser close" yaml:"enable-session-cookies"`
	// EnableLoginHandler indicates we want the login handler enabled
	EnableLoginHandler bool `env:"ENABLE_LOGIN_HANDLER" json:"enable-login-handler" usage:"enables the handling of the refresh tokens" yaml:"enable-login-handler"`
	// EnableTokenHeader adds the JWT token to the upstream authentication headers
	EnableTokenHeader bool `env:"ENABLE_TOKEN_HEADER" json:"enable-token-header" usage:"enables the token authentication header X-Auth-Token to upstream" yaml:"enable-token-header"`
	// EnableAuthorizationHeader indicates we should pass the authorization header to the upstream endpoint
	EnableAuthorizationHeader bool `env:"ENABLE_AUTHORIZATION_HEADER" json:"enable-authorization-header" usage:"adds the authorization header to the proxy request" yaml:"enable-authorization-header"`
	// EnableAuthorizationCookies indicates we should pass the authorization cookies to the upstream endpoint
	EnableAuthorizationCookies bool `env:"ENABLE_AUTHORIZATION_COOKIES" json:"enable-authorization-cookies" usage:"adds the authorization cookies to the uptream proxy request" yaml:"enable-authorization-cookies"`
	// EnableHTTPSRedirect indicate we should redirection http -> https
	EnableHTTPSRedirect bool `env:"ENABLE_HTTPS_REDIRECT" json:"enable-https-redirection" usage:"enable the http to https redirection on the http service" yaml:"enable-https-redirection"`
	// EnableProfiling indicates if profiles is switched on
	EnableProfiling bool `env:"ENABLE_PROFILING" json:"enable-profiling" usage:"switching on the golang profiling via pprof on /debug/pprof, /debug/pprof/heap etc" yaml:"enable-profiling"`
	// EnableMetrics indicates if the metrics is enabled
	EnableMetrics bool `env:"ENABLE_METRICS" json:"enable-metrics" usage:"enable the prometheus metrics collector on /oauth/metrics" yaml:"enable-metrics"`
	// EnableBrowserXSSFilter indicates you want the filter on
	EnableBrowserXSSFilter bool `env:"ENABLE_BROWSER_XSS_FILTER" json:"filter-browser-xss" usage:"enable the adds the X-XSS-Protection header with mode=block" yaml:"filter-browser-xss"`
	// EnableContentNoSniff indicates you want the filter on
	EnableContentNoSniff bool `env:"ENABLE_CONTENT_NO_SNIFF" json:"filter-content-nosniff" usage:"adds the X-Content-Type-Options header with the value nosniff" yaml:"filter-content-nosniff"`
	// EnableFrameDeny indicates the filter is on
	EnableFrameDeny bool `env:"ENABLE_FRAME_DENY" json:"filter-frame-deny" usage:"enable to the frame deny header" yaml:"filter-frame-deny"`
	// ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value
	ContentSecurityPolicy string `env:"CONTENT_SECURITY_POLICY" json:"content-security-policy" usage:"specify the content security policy" yaml:"content-security-policy"`
	// LocalhostMetrics indicates that metrics can only be consumed from localhost
	LocalhostMetrics bool `env:"LOCALHOST_METRICS" json:"localhost-metrics" usage:"enforces the metrics page can only been requested from 127.0.0.1" yaml:"localhost-metrics"`
	// EnableCompression enables gzip compression for response
	EnableCompression bool `env:"ENABLE_COMPRESSION" json:"enable-compression" usage:"enable gzip compression for response" yaml:"enable-compression"`
	// EnablePKCE, only S256 code challenge method is supported
	EnablePKCE bool `env:"ENABLE_PKCE" json:"enable-pkce" usage:"enable pkce for auth code flow, only S256 code challenge supported" yaml:"enable-pkce"`

	EnableUma   bool          `env:"ENABLE_UMA"    json:"enable-uma"    usage:"enable uma authorization, please don't use it in production, we would like to receive feedback" yaml:"enable-uma"`
	EnableOpa   bool          `env:"ENABLE_OPA"    json:"enable-opa"    usage:"enable authorization with external Open policy agent"                                           yaml:"enable-opa"`
	OpaTimeout  time.Duration `env:"OPA_TIMEOUT"   json:"opa-timeout"   usage:"timeout for connection to OPA"                                                                  yaml:"opa-timeout"`
	OpaAuthzURI string        `env:"OPA_AUTHZ_URI" json:"opa-authz-uri" usage:"OPA endpoint address with path"                                                                 yaml:"opa-authz-uri"`

	PatRetryCount    int           `env:"PAT_RETRY_COUNT"    json:"pat-retry-count"    usage:"number of retries to get PAT"        yaml:"pat-retry-count"`
	PatRetryInterval time.Duration `env:"PAT_RETRY_INTERVAL" json:"pat-retry-interval" usage:"interval between retries to get PAT" yaml:"pat-retry-interval"`

	// AccessTokenDuration is default duration applied to the access token cookie
	AccessTokenDuration time.Duration `env:"ACCESS_TOKEN_DURATION" json:"access-token-duration" usage:"fallback cookie duration for the access token when using refresh tokens" yaml:"access-token-duration"`
	// CookieDomain is a list of domains the cookie is available to
	CookieDomain string `env:"COOKIE_DOMAIN" json:"cookie-domain" usage:"domain the access cookie is available to, defaults host header" yaml:"cookie-domain"`
	// CookieAccessName is the name of the access cookie holding the access token
	CookieAccessName string `env:"COOKIE_ACCESS_NAME" json:"cookie-access-name" usage:"name of the cookie used to hold the access token" yaml:"cookie-access-name"`
	// CookieIdName is the name of the id token cookie holding the id token
	CookieIDTokenName string `env:"COOKIE_ID_TOKEN_NAME" json:"cookie-id-token-name" usage:"name of the cookie used to hold id token" yaml:"cookie-id-token-name"`
	// CookieRefreshName is the name of the refresh cookie
	CookieRefreshName string `env:"COOKIE_REFRESH_NAME" json:"cookie-refresh-name" usage:"name of the cookie used to hold the encrypted refresh token" yaml:"cookie-refresh-name"`
	// CookieOAuthStateName is the name of the Oauth Token request state
	CookieOAuthStateName string `env:"COOKIE_OAUTH_STATE_NAME" json:"cookie-oauth-state-name" usage:"name of the cookie used to hold the Oauth request state" yaml:"cookie-oauth-state-name"`
	// CookieRequestURIName is the name of the Request Uri cookie
	CookieRequestURIName string `env:"COOKIE_REQUEST_URI_NAME" json:"cookie-request-uri-name" usage:"name of the cookie used to hold the request uri" yaml:"cookie-request-uri-name"`
	// CookiePKCEName is the name of PKCE code verifier cookie
	CookiePKCEName string `env:"COOKIE_PKCE_NAME" json:"cookie-pkce-name" usage:"name of the cookie used to hold PKCE code verifier" yaml:"cookie-pkce-name"`
	// SecureCookie enforces the cookie as secure
	SecureCookie bool `env:"SECURE_COOKIE" json:"secure-cookie" usage:"enforces the cookie to be secure" yaml:"secure-cookie"`
	// HTTPOnlyCookie enforces the cookie as http only
	HTTPOnlyCookie bool `env:"HTTP_ONLY_COOKIE" json:"http-only-cookie" usage:"enforces the cookie is in http only mode" yaml:"http-only-cookie"`
	// SameSiteCookie enforces cookies to be send only to same site requests.
	SameSiteCookie string `env:"SAME_SITE_COOKIE" json:"same-site-cookie" usage:"enforces cookies to be send only to same site requests according to the policy (can be Strict|Lax|None)" yaml:"same-site-cookie"`

	// MatchClaims is a series of checks, the claims in the token must match those here
	MatchClaims map[string]string `json:"match-claims" usage:"keypair values for matching access token claims e.g. aud=myapp, iss=http://example.*" yaml:"match-claims"`
	// AddClaims is a series of claims that should be added to the auth headers
	AddClaims []string `json:"add-claims" usage:"extra claims from the token and inject into headers, e.g given_name -> X-Auth-Given-Name" yaml:"add-claims"`

	// TLSCertificate is the location for a tls certificate
	TLSCertificate string `env:"TLS_CERTIFICATE" json:"tls-cert" usage:"path to ths TLS certificate" yaml:"tls-cert"`
	// TLSPrivateKey is the location of a tls private key
	TLSPrivateKey string `env:"TLS_PRIVATE_KEY" json:"tls-private-key" usage:"path to the private key for TLS" yaml:"tls-private-key"`
	// TLSCaCertificate is the CA certificate which the client cert must be signed
	TLSCaCertificate string `env:"TLS_CA_CERTIFICATE" json:"tls-ca-certificate" usage:"path to the ca certificate used for signing requests" yaml:"tls-ca-certificate"`
	// TLSCaPrivateKey is the CA private key used for signing
	TLSCaPrivateKey string `env:"TLS_CA_PRIVATE_KEY" json:"tls-ca-key" usage:"path the ca private key, used by the forward signing proxy" yaml:"tls-ca-key"`
	// TLSClientCertificate is path to a client certificate to use for outbound connections
	TLSClientCertificate string `env:"TLS_CLIENT_CERTIFICATE" json:"tls-client-certificate" usage:"path to the client certificate for outbound connections in reverse and forwarding proxy modes" yaml:"tls-client-certificate"`
	// SkipUpstreamTLSVerify skips the verification of any upstream tls
	SkipUpstreamTLSVerify bool `env:"SKIP_UPSTREAM_TLS_VERIFY" json:"skip-upstream-tls-verify" usage:"skip the verification of any upstream TLS" yaml:"skip-upstream-tls-verify"`
	// TLSMinVersion specifies server minimal TLS version
	TLSMinVersion string `env:"TLS_MIN_VERSION" json:"tls-min-version" usage:"specify server minimal TLS version one of tlsv1.0,tlsv1.1,tlsv1.2,tlsv1.3" yaml:"tls-min-version"`

	// TLSAdminCertificate is the location for a tls certificate for admin https endpoint. Defaults to TLSCertificate.
	TLSAdminCertificate string `env:"TLS_ADMIN_CERTIFICATE" json:"tls-admin-cert" usage:"path to ths TLS certificate" yaml:"tls-admin-cert"`
	// TLSAdminPrivateKey is the location of a tls private key for admin https endpoint. Default to TLSPrivateKey
	TLSAdminPrivateKey string `env:"TLS_ADMIN_PRIVATE_KEY" json:"tls-admin-private-key" usage:"path to the private key for TLS" yaml:"tls-admin-private-key"`
	// TLSCaCertificate is the CA certificate which the client cert must be signed
	TLSAdminCaCertificate string `env:"TLS_ADMIN_CA_CERTIFICATE" json:"tls-admin-ca-certificate" usage:"path to the ca certificate used for signing requests" yaml:"tls-admin-ca-certificate"`
	// TLSAdinClientCertificate is path to a client certificate to use for outbound connections
	TLSAdminClientCertificate string `env:"TLS_ADMIN_CLIENT_CERTIFICATE" json:"tls-admin-client-certificate" usage:"path to the client certificate for outbound connections in reverse and forwarding proxy modes" yaml:"tls-admin-client-certificate"`

	// CorsOrigins is a list of origins permitted
	CorsOrigins []string `json:"cors-origins" usage:"origins to add to the CORE origins control (Access-Control-Allow-Origin)" yaml:"cors-origins"`
	// CorsMethods is a set of access control methods
	CorsMethods []string `json:"cors-methods" usage:"methods permitted in the access control (Access-Control-Allow-Methods)" yaml:"cors-methods"`
	// CorsHeaders is a set of cors headers
	CorsHeaders []string `json:"cors-headers" usage:"set of headers to add to the CORS access control (Access-Control-Allow-Headers)" yaml:"cors-headers"`
	// CorsExposedHeaders are the exposed header fields
	CorsExposedHeaders []string `json:"cors-exposed-headers" usage:"expose cors headers access control (Access-Control-Expose-Headers)" yaml:"cors-exposed-headers"`
	// CorsCredentials set the credentials flag
	CorsCredentials bool `env:"CORS_CREDENTIALS" json:"cors-credentials" usage:"credentials access control header (Access-Control-Allow-Credentials)" yaml:"cors-credentials"`
	// CorsMaxAge is the age for CORS
	CorsMaxAge time.Duration `env:"CORS_MAX_AGE" json:"cors-max-age" usage:"max age applied to cors headers (Access-Control-Max-Age)" yaml:"cors-max-age"`
	// Hostnames is a list of hostname's the service should response to
	Hostnames []string `json:"hostnames" usage:"list of hostnames the service will respond to" yaml:"hostnames"`

	// Store is a url for a store resource, used to hold the refresh tokens
	StoreURL string `env:"STORE_URL" json:"store-url" usage:"url for the storage subsystem, e.g redis://127.0.0.1:6379, file:///etc/tokens.file" yaml:"store-url"`
	// EncryptionKey is the encryption key used to encrypt the refresh token
	EncryptionKey string `env:"ENCRYPTION_KEY" json:"encryption-key" usage:"encryption key used to encryption the session state" yaml:"encryption-key"`

	// NoProxy it passed through all middleware but not proxy to upstream, useful when using as auth backend for forward-auth (nginx, traefik)
	NoProxy bool `env:"NO_PROXY" json:"no-proxy" usage:"do not proxy requests to upstream, useful for forward-auth usage (with nginx, traefik)" yaml:"no-proxy"`
	// NoRedirects informs we should hand back a 401 not a redirect
	NoRedirects bool `env:"NO_REDIRECTS" json:"no-redirects" usage:"do not have back redirects when no authentication is present, 401 them" yaml:"no-redirects"`
	// SkipTokenVerification tells the service to skip verifying the access token - for testing purposes
	SkipTokenVerification bool `env:"SKIP_TOKEN_VERIFICATION" json:"skip-token-verification" usage:"TESTING ONLY; bypass token verification, only expiration and roles enforced" yaml:"skip-token-verification"`
	// according RFC issuer should not be checked on access token, this will be default true in future
	SkipAccessTokenIssuerCheck bool `env:"SKIP_ACCESS_TOKEN_ISSUER_CHECK" json:"skip-access-token-issuer-check" usage:"according RFC issuer should not be checked on access token, this will be default true in future" yaml:"skip-access-token-issuer-check"`
	// according RFC client id should not be checked on access token, this will be default true in future
	SkipAccessTokenClientIDCheck bool `env:"SKIP_ACCESS_TOKEN_CLIENT_ID_CHECK" json:"skip-access-token-clientid-check" usage:"according RFC client id should not be checked on access token, this will be default true in future" yaml:"skip-access-token-clientid-check"`
	// skip authorization header (e.g. if authorization header is used by application behind gatekeeper)
	SkipAuthorizationHeaderIdentity bool `env:"SKIP_AUTHORIZATION_HEADER_IDENTITY" json:"skip-authorization-header-identity" usage:"skip authorization header identity, means that we won't be extracting token from authorization header (e.g. if authorization header is used only by application behind gatekeeper)" yaml:"skip-authorization-header-identity"`
	// UpstreamKeepalives specifies whether we use keepalives on the upstream
	UpstreamKeepalives bool `env:"UPSTREAM_KEEPALIVES" json:"upstream-keepalives" usage:"enables or disables the keepalive connections for upstream endpoint" yaml:"upstream-keepalives"`
	// UpstreamTimeout is the maximum amount of time a dial will wait for a connect to complete
	UpstreamTimeout time.Duration `env:"UPSTREAM_TIMEOUT" json:"upstream-timeout" usage:"maximum amount of time a dial will wait for a connect to complete" yaml:"upstream-timeout"`
	// UpstreamKeepaliveTimeout is the upstream keepalive timeout
	UpstreamKeepaliveTimeout time.Duration `env:"UPSTREAM_KEEPALIVE_TIMEOUT" json:"upstream-keepalive-timeout" usage:"specifies the keep-alive period for an active network connection" yaml:"upstream-keepalive-timeout"`
	// UpstreamTLSHandshakeTimeout is the timeout for upstream to tls handshake
	UpstreamTLSHandshakeTimeout time.Duration `env:"UPSTREAM_TLS_HANDSHAKE_TIMEOUT" json:"upstream-tls-handshake-timeout" usage:"the timeout placed on the tls handshake for upstream" yaml:"upstream-tls-handshake-timeout"`
	// UpstreamResponseHeaderTimeout is the timeout for upstream header response
	UpstreamResponseHeaderTimeout time.Duration `env:"UPSTREAM_RESPONSE_HEADER_TIMEOUT" json:"upstream-response-header-timeout" usage:"the timeout placed on the response header for upstream" yaml:"upstream-response-header-timeout"`
	// UpstreamExpectContinueTimeout is the timeout expect continue for upstream
	UpstreamExpectContinueTimeout time.Duration `env:"UPSTREAM_EXPECT_CONTINUE_TIMEOUT" json:"upstream-expect-continue-timeout" usage:"the timeout placed on the expect continue for upstream" yaml:"upstream-expect-continue-timeout"`

	// Verbose switches on debug logging
	Verbose bool `env:"VERBOSE" json:"verbose" usage:"switch on debug / verbose logging" yaml:"verbose"`
	// EnableProxyProtocol controls the proxy protocol
	EnableProxyProtocol bool `env:"ENABLE_PROXY_PROTOCOL" json:"enabled-proxy-protocol" usage:"enable proxy protocol" yaml:"enabled-proxy-protocol"`

	// MaxIdleConns is the max idle connections to keep alive, ready for reuse
	MaxIdleConns int `env:"MAX_IDLE_CONNS" json:"max-idle-connections" usage:"max idle upstream / keycloak connections to keep alive, ready for reuse" yaml:"max-idle-connections"`
	// MaxIdleConnsPerHost limits the number of idle connections maintained per host
	MaxIdleConnsPerHost int `env:"MAX_IDLE_CONNS_PER_HOST" json:"max-idle-connections-per-host" usage:"limits the number of idle connections maintained per host" yaml:"max-idle-connections-per-host"`

	// ServerGraceTimeout is the time to wait for the server to shutdown
	ServerGraceTimeout time.Duration `env:"SERVER_GRACE_TIMEOUT" json:"server-grace-timeout" usage:"the server wait before closing the server" yaml:"server-grace-timeout"`
	// ServerReadTimeout is the read timeout on the http server
	ServerReadTimeout time.Duration `env:"SERVER_READ_TIMEOUT" json:"server-read-timeout" usage:"the server read timeout on the http server" yaml:"server-read-timeout"`
	// ServerWriteTimeout is the write timeout on the http server
	ServerWriteTimeout time.Duration `env:"SERVER_WRITE_TIMEOUT" json:"server-write-timeout" usage:"the server write timeout on the http server" yaml:"server-write-timeout"`
	// ServerIdleTimeout is the idle timeout on the http server
	ServerIdleTimeout time.Duration `env:"SERVER_IDLE_TIMEOUT" json:"server-idle-timeout" usage:"the server idle timeout on the http server" yaml:"server-idle-timeout"`

	// UseLetsEncrypt controls if we should use letsencrypt to retrieve certificates
	UseLetsEncrypt bool `env:"USE_LETS_ENCRYPT" json:"use-letsencrypt" usage:"use letsencrypt for certificates" yaml:"use-letsencrypt"`

	// LetsEncryptCacheDir is the path to store letsencrypt certificates
	LetsEncryptCacheDir string `env:"LETS_ENCRYPT_CACHE_DIR" json:"letsencrypt-cache-dir" usage:"path where cached letsencrypt certificates are stored" yaml:"letsencrypt-cache-dir"`

	// SignInPage is the relative url for the sign in page
	SignInPage string `env:"SIGN_IN_PAGE" json:"sign-in-page" usage:"path to custom template displayed for signin" yaml:"sign-in-page"`
	// ForbiddenPage is a access forbidden page
	ForbiddenPage string `env:"FORBIDDEN_PAGE" json:"forbidden-page" usage:"path to custom template used for access forbidden" yaml:"forbidden-page"`
	// ErrorPage is the relative url for the custom error page
	ErrorPage string `env:"ERROR_PAGE" json:"error-page" usage:"path to custom template displayed for http.StatusBadRequest" yaml:"error-page"`
	// Tags is passed to the templates
	Tags map[string]string `json:"tags" usage:"keypairs passed to the templates at render,e.g title=Page" yaml:"tags"`

	ForwardingGrantType string `env:"FORWARDING_GRANT_TYPE" json:"forwarding-grant-type" usage:"grant-type to use when logging into the openid provider, can be one of password, client_credentials" yaml:"forwarding-grant-type"`
	// ForwardingUsername is the username to login to the oauth service
	ForwardingUsername string `env:"FORWARDING_USERNAME" json:"forwarding-username" usage:"username to use when logging into the openid provider" yaml:"forwarding-username"`
	// ForwardingPassword is the password to use for the above
	ForwardingPassword string `env:"FORWARDING_PASSWORD" json:"forwarding-password" usage:"password to use when logging into the openid provider" yaml:"forwarding-password"`
	// ForwardingDomains is a collection of domains to signs
	ForwardingDomains []string `json:"forwarding-domains" usage:"list of domains which should be signed; everything else is relayed unsigned" yaml:"forwarding-domains"`

	// DisableAllLogging indicates no logging at all
	DisableAllLogging bool `env:"DISABLE_ALL_LOGGING" json:"disable-all-logging" usage:"disables all logging to stdout and stderr" yaml:"disable-all-logging"`
	// this is non-configurable field, derived from discoveryurl at initialization
	Realm               string
	DiscoveryURI        *url.URL
	OpaAuthzURL         *url.URL
	IsDiscoverURILegacy bool
}

// NewDefaultConfig returns a initialized config
func NewDefaultConfig() *Config {
	var hostnames []string
	if name, err := os.Hostname(); err == nil {
		hostnames = append(hostnames, name)
	}
	hostnames = append(hostnames, []string{"localhost", "127.0.0.1", "::1"}...)

	return &Config{
		AccessTokenDuration:           time.Duration(constant.FallbackAccessTokenDuration) * time.Hour,
		CookieAccessName:              constant.AccessCookie,
		CookieIDTokenName:             constant.IDTokenCookie,
		CookieRefreshName:             constant.RefreshCookie,
		CookieOAuthStateName:          constant.RequestStateCookie,
		CookieRequestURIName:          constant.RequestURICookie,
		CookiePKCEName:                constant.PKCECookie,
		EnableAuthorizationCookies:    true,
		EnableAuthorizationHeader:     true,
		EnableDefaultDeny:             true,
		EnableSessionCookies:          true,
		EnableTokenHeader:             true,
		HTTPOnlyCookie:                true,
		Headers:                       make(map[string]string),
		AllowedQueryParams:            make(map[string]string),
		DefaultAllowedQueryParams:     make(map[string]string),
		LetsEncryptCacheDir:           "./cache/",
		MatchClaims:                   make(map[string]string),
		MaxIdleConns:                  constant.DefaultMaxIdleConns,
		MaxIdleConnsPerHost:           constant.DefaultMaxIdleConnsPerHost,
		OAuthURI:                      "/oauth",
		OpenIDProviderTimeout:         constant.DefaultOpenIDProviderTimeout,
		OpenIDProviderRetryCount:      constant.DefaultOpenIDProviderRetryCount,
		PreserveHost:                  false,
		SelfSignedTLSExpiration:       constant.DefaultSelfSignedTLSExpiration,
		SelfSignedTLSHostnames:        hostnames,
		RequestIDHeader:               "X-Request-ID",
		ResponseHeaders:               make(map[string]string),
		SameSiteCookie:                constant.SameSiteLax,
		Scopes:                        []string{"email", "profile"},
		SecureCookie:                  true,
		ServerGraceTimeout:            constant.DefaultServerGraceTimeout,
		ServerIdleTimeout:             constant.DefaultServerIdleTimeout,
		ServerReadTimeout:             constant.DefaultServerReadTimeout,
		ServerWriteTimeout:            constant.DefaultServerWriteTimeout,
		SkipOpenIDProviderTLSVerify:   false,
		SkipUpstreamTLSVerify:         true,
		SkipAccessTokenIssuerCheck:    true,
		SkipAccessTokenClientIDCheck:  true,
		Tags:                          make(map[string]string),
		TLSMinVersion:                 "tlsv1.3",
		UpstreamExpectContinueTimeout: constant.DefaultUpstreamExpectContinueTimeout,
		UpstreamKeepaliveTimeout:      constant.DefaultUpstreamKeepaliveTimeout,
		UpstreamKeepalives:            true,
		UpstreamResponseHeaderTimeout: constant.DefaultUpstreamResponseHeaderTimeout,
		UpstreamTLSHandshakeTimeout:   constant.DefaultUpstreamTLSHandshakeTimeout,
		UpstreamTimeout:               constant.DefaultUpstreamTimeout,
		UseLetsEncrypt:                false,
		ForwardingGrantType:           core.GrantTypeUserCreds,
		PatRetryCount:                 constant.DefaultPatRetryCount,
		PatRetryInterval:              constant.DefaultPatRetryInterval,
		OpaTimeout:                    constant.DefaultOpaTimeout,
	}
}

func (r *Config) SetResources(resources []*authorization.Resource) {
	r.Resources = resources
}

func (r *Config) GetResources() []*authorization.Resource {
	return r.Resources
}

func (r *Config) GetHeaders() map[string]string {
	return r.Headers
}

func (r *Config) GetMatchClaims() map[string]string {
	return r.MatchClaims
}

func (r *Config) GetTags() map[string]string {
	return r.Tags
}

func (r *Config) GetAllowedQueryParams() map[string]string {
	return r.AllowedQueryParams
}

func (r *Config) GetDefaultAllowedQueryParams() map[string]string {
	return r.DefaultAllowedQueryParams
}

// readConfigFile reads and parses the configuration file
func (r *Config) ReadConfigFile(filename string) error {
	content, err := os.ReadFile(filename)

	if err != nil {
		return err
	}
	// step: attempt to un-marshal the data
	switch ext := filepath.Ext(filename); ext {
	case "json":
		//nolint:musttag
		err = json.Unmarshal(content, r)
	default:
		err = yaml.Unmarshal(content, r)
	}

	return err
}

func (r *Config) Update() error {
	updateRegistry := []func() error{
		r.updateDiscoveryURI,
		r.extractDiscoveryURIComponents,
	}

	for _, updateFunc := range updateRegistry {
		if err := updateFunc(); err != nil {
			return err
		}
	}

	return nil
}

// IsValid validates if the config is valid
func (r *Config) IsValid() error {
	if r.ListenAdmin == r.Listen {
		r.ListenAdmin = ""
	}

	if r.ListenAdminScheme == "" {
		r.ListenAdminScheme = constant.SecureScheme
	}

	validationRegistry := []func() error{
		r.isListenValid,
		r.isListenAdminSchemeValid,
		r.isOpenIDProviderProxyValid,
		r.isMaxIdlleConnValid,
		r.isSameSiteValid,
		r.isTLSFilesValid,
		r.isAdminTLSFilesValid,
		r.isLetsEncryptValid,
		r.isTLSMinValid,
		r.isForwardingProxySettingsValid,
		r.isReverseProxySettingsValid,
	}

	for _, validationFunc := range validationRegistry {
		if err := validationFunc(); err != nil {
			return err
		}
	}

	return nil
}

// HasCustomSignInPage checks if there is a custom sign in  page
func (r *Config) HasCustomSignInPage() bool {
	return r.SignInPage != ""
}

// HasForbiddenPage checks if there is a custom forbidden page
func (r *Config) HasCustomForbiddenPage() bool {
	return r.ForbiddenPage != ""
}

// HasCustomErrorPage checks if there is a custom error page
func (r *Config) HasCustomErrorPage() bool {
	return r.ErrorPage != ""
}

func (r *Config) isListenValid() error {
	if r.Listen == "" {
		return errors.New("you have not specified the listening interface")
	}
	return nil
}

func (r *Config) isListenAdminSchemeValid() error {
	if r.ListenAdminScheme != constant.SecureScheme &&
		r.ListenAdminScheme != constant.UnsecureScheme {
		return errors.New("scheme for admin listener must be one of [http, https]")
	}
	return nil
}

func (r *Config) isOpenIDProviderProxyValid() error {
	if r.OpenIDProviderProxy != "" {
		_, err := url.ParseRequestURI(r.OpenIDProviderProxy)

		if err != nil {
			return errors.New("invalid proxy address for open IDP provider proxy")
		}
	}

	return nil
}

func (r *Config) isMaxIdlleConnValid() error {
	if r.MaxIdleConns <= 0 {
		return errors.New("max-idle-connections must be a number > 0")
	}

	if r.MaxIdleConnsPerHost < 0 || r.MaxIdleConnsPerHost > r.MaxIdleConns {
		return errors.New(
			"maxi-idle-connections-per-host must be a " +
				"number > 0 and <= max-idle-connections",
		)
	}
	return nil
}

func (r *Config) isSameSiteValid() error {
	if r.SameSiteCookie != "" && r.SameSiteCookie != constant.SameSiteStrict &&
		r.SameSiteCookie != constant.SameSiteLax && r.SameSiteCookie != constant.SameSiteNone {
		return errors.New("same-site-cookie must be one of Strict|Lax|None")
	}
	return nil
}

//nolint:cyclop
func (r *Config) isTLSFilesValid() error {
	if r.TLSCertificate != "" && r.TLSPrivateKey == "" {
		return errors.New("you have not provided a private key")
	}

	if r.TLSPrivateKey != "" && r.TLSCertificate == "" {
		return errors.New("you have not provided a certificate file")
	}

	if r.TLSCertificate != "" && !utils.FileExists(r.TLSCertificate) {
		return fmt.Errorf("the tls certificate %s does not exist", r.TLSCertificate)
	}

	if r.TLSPrivateKey != "" && !utils.FileExists(r.TLSPrivateKey) {
		return fmt.Errorf("the tls private key %s does not exist", r.TLSPrivateKey)
	}

	if r.TLSCaCertificate != "" && !utils.FileExists(r.TLSCaCertificate) {
		return fmt.Errorf(
			"the tls ca certificate file %s does not exist",
			r.TLSCaCertificate,
		)
	}

	if r.TLSClientCertificate != "" && !utils.FileExists(r.TLSClientCertificate) {
		return fmt.Errorf(
			"the tls client certificate %s does not exist",
			r.TLSClientCertificate,
		)
	}

	return nil
}

//nolint:cyclop
func (r *Config) isAdminTLSFilesValid() error {
	if r.TLSAdminCertificate != "" && r.TLSAdminPrivateKey == "" {
		return errors.New("you have not provided a private key for admin endpoint")
	}

	if r.TLSAdminPrivateKey != "" && r.TLSAdminCertificate == "" {
		return errors.New(
			"you have not provided a certificate file for admin endpoint",
		)
	}

	if r.TLSAdminCertificate != "" && !utils.FileExists(r.TLSAdminCertificate) {
		return fmt.Errorf(
			"the tls certificate %s does not exist for admin endpoint",
			r.TLSAdminCertificate,
		)
	}

	if r.TLSAdminPrivateKey != "" && !utils.FileExists(r.TLSAdminPrivateKey) {
		return fmt.Errorf(
			"the tls private key %s does not exist for admin endpoint",
			r.TLSAdminPrivateKey,
		)
	}

	if r.TLSAdminCaCertificate != "" && !utils.FileExists(r.TLSAdminCaCertificate) {
		return fmt.Errorf(
			"the tls ca certificate file %s does not exist for admin endpoint",
			r.TLSAdminCaCertificate,
		)
	}

	if r.TLSAdminClientCertificate != "" && !utils.FileExists(r.TLSAdminClientCertificate) {
		return fmt.Errorf(
			"the tls client certificate %s does not exist for admin endpoint",
			r.TLSAdminClientCertificate,
		)
	}

	return nil
}

func (r *Config) isLetsEncryptValid() error {
	if r.UseLetsEncrypt && r.LetsEncryptCacheDir == "" {
		return apperrors.ErrLetsEncryptMissingCacheDir
	}
	return nil
}

func (r *Config) isTLSMinValid() error {
	switch strings.ToLower(r.TLSMinVersion) {
	case "":
		return apperrors.ErrMinimalTLSVersionEmpty
	case "tlsv1.0":
	case "tlsv1.1":
	case "tlsv1.2":
	case "tlsv1.3":
	default:
		return apperrors.ErrInvalidMinimalTLSVersion
	}
	return nil
}

func (r *Config) isForwardingProxySettingsValid() error {
	if r.EnableForwarding {
		validationRegistry := []func() error{
			r.isClientIDValid,
			r.isDiscoveryURLValid,
			r.isForwardingGrantValid,
			func() error {
				if r.TLSCertificate != "" {
					return errors.New("you don't need to specify a " +
						"tls-certificate, use tls-ca-certificate instead",
					)
				}
				return nil
			},
			func() error {
				if r.TLSPrivateKey != "" {
					return errors.New("you don't need to specify the " +
						"tls-private-key, use tls-ca-key instead",
					)
				}
				return nil
			},
		}

		for _, validationFunc := range validationRegistry {
			if err := validationFunc(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *Config) isReverseProxySettingsValid() error {
	if !r.EnableForwarding {
		validationRegistry := []func() error{
			r.isNoProxyValid,
			r.isUpstreamValid,
			r.isDefaultDenyValid,
			r.isExternalAuthzValid,
			r.isTokenVerificationSettingsValid,
			r.isResourceValid,
			r.isMatchClaimValid,
			r.isPKCEValid,
		}

		for _, validationFunc := range validationRegistry {
			if err := validationFunc(); err != nil {
				return err
			}
		}

		return nil
	}

	return nil
}

func (r *Config) isTokenVerificationSettingsValid() error {
	// step: if the skip verification is off, we need the below
	if !r.SkipTokenVerification {
		validationRegistry := []func() error{
			r.isClientIDValid,
			r.isDiscoveryURLValid,
			func() error {
				r.RedirectionURL = strings.TrimSuffix(r.RedirectionURL, "/")
				return nil
			},
			r.isSecurityFilterValid,
			r.isTokenEncryptionValid,
			r.isSecureCookieValid,
			r.isStoreURLValid,
		}

		for _, validationFunc := range validationRegistry {
			if err := validationFunc(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *Config) isNoProxyValid() error {
	if r.NoProxy && !r.NoRedirects && r.RedirectionURL != "" {
		return errors.New("when in forward-auth mode - " +
			"noproxy=true with noredirect=false, redirectionURL " +
			"should not be set, will be composed from X-FORWARDED-* headers",
		)
	}
	return nil
}

func (r *Config) isUpstreamValid() error {
	if r.Upstream == "" && !r.NoProxy {
		return errors.New("you have not specified an upstream endpoint to proxy to")
	}

	if !r.NoProxy {
		if _, err := url.ParseRequestURI(r.Upstream); err != nil {
			return fmt.Errorf("the upstream endpoint is invalid, %s", err)
		}
	}

	if r.SkipUpstreamTLSVerify && r.UpstreamCA != "" {
		return fmt.Errorf("you cannot skip upstream tls and load a root ca: %s to verify it", r.UpstreamCA)
	}

	return nil
}

func (r *Config) isClientIDValid() error {
	if r.ClientID == "" {
		return errors.New("you have not specified the client id")
	}
	return nil
}

func (r *Config) isDiscoveryURLValid() error {
	if r.DiscoveryURL == "" {
		return errors.New("you have not specified the discovery url")
	}
	return nil
}

func (r *Config) isForwardingGrantValid() error {
	if r.ForwardingGrantType == core.GrantTypeUserCreds {
		if r.ForwardingUsername == "" {
			return errors.New("no forwarding username")
		}

		if r.ForwardingPassword == "" {
			return errors.New("no forwarding password")
		}
	}

	if r.ForwardingGrantType == core.GrantTypeClientCreds {
		if r.ClientSecret == "" {
			return errors.New("you have not specified the client secret")
		}
	}

	return nil
}

func (r *Config) isSecurityFilterValid() error {
	if !r.EnableSecurityFilter {
		if r.EnableHTTPSRedirect {
			return errors.New(
				"the security filter must be switch on for this feature: http-redirect",
			)
		}

		if r.EnableBrowserXSSFilter {
			return errors.New(
				"the security filter must be switch on " +
					"for this feature: brower-xss-filter",
			)
		}

		if r.EnableFrameDeny {
			return errors.New(
				"the security filter must be switch on " +
					"for this feature: frame-deny-filter",
			)
		}

		if r.ContentSecurityPolicy != "" {
			return errors.New(
				"the security filter must be switch on " +
					"for this feature: content-security-policy",
			)
		}

		if len(r.Hostnames) > 0 {
			return errors.New(
				"the security filter must be switch on for this feature: hostnames",
			)
		}
	}

	return nil
}

func (r *Config) isTokenEncryptionValid() error {
	if (r.EnableEncryptedToken || r.ForceEncryptedCookie) &&
		r.EncryptionKey == "" {
		return errors.New(
			"you have not specified an encryption key for encoding the access token",
		)
	}

	if r.EnableRefreshTokens && r.EncryptionKey == "" {
		return errors.New(
			"enable refresh tokens requires encryption key to be defined",
		)
	}

	if r.EnableRefreshTokens && (len(r.EncryptionKey) != 16 &&
		len(r.EncryptionKey) != 32) {
		return fmt.Errorf(
			"the encryption key (%d) must be either 16 or 32 "+
				"characters for AES-128/AES-256 selection",
			len(r.EncryptionKey),
		)
	}

	return nil
}

func (r *Config) isSecureCookieValid() error {
	if !r.NoRedirects && r.SecureCookie && r.RedirectionURL != "" &&
		!strings.HasPrefix(r.RedirectionURL, "https") {
		return errors.New(
			"the cookie is set to secure but your redirection url is non-tls",
		)
	}

	return nil
}

func (r *Config) isStoreURLValid() error {
	if r.StoreURL != "" {
		if _, err := url.ParseRequestURI(r.StoreURL); err != nil {
			return fmt.Errorf("the store url is invalid, error: %s", err)
		}
	}

	return nil
}

func (r *Config) isResourceValid() error {
	// step: add custom http methods for check
	if r.CustomHTTPMethods != nil {
		for _, customHTTPMethod := range r.CustomHTTPMethods {
			chi.RegisterMethod(customHTTPMethod)
			utils.AllHTTPMethods = append(utils.AllHTTPMethods, customHTTPMethod)
		}
	}

	// check: ensure each of the resource are valid
	for _, resource := range r.Resources {
		if err := resource.Valid(); err != nil {
			return err
		}

		if resource.URL == constant.AllPath && (r.EnableDefaultDeny || r.EnableDefaultDenyStrict) {
			switch resource.WhiteListed {
			case true:
				return apperrors.ErrDefaultDenyWhitelistConflict
			default:
				return apperrors.ErrDefaultDenyUserDefinedConflict
			}
		}
	}

	return nil
}

func (r *Config) isMatchClaimValid() error {
	// step: validate the claims are validate regex's
	for k, claim := range r.MatchClaims {
		if _, err := regexp.Compile(claim); err != nil {
			return fmt.Errorf(
				"the claim matcher: %s for claim: %s is not a valid regex",
				claim,
				k,
			)
		}
	}

	return nil
}

func (r *Config) isExternalAuthzValid() error {
	if r.EnableUma && r.EnableOpa {
		return errors.New(
			"only one type of external authz can be enabled at once",
		)
	}

	if r.EnableUma {
		if r.ClientID == "" || r.ClientSecret == "" {
			return errors.New(
				"enable uma requires client credentials",
			)
		}
		if !r.NoRedirects {
			return errors.New(
				"enable-uma requires no-redirects option",
			)
		}
	} else if r.EnableOpa {
		authzURL, err := url.ParseRequestURI(r.OpaAuthzURI)

		if err != nil {
			return fmt.Errorf("not valid OPA authz URL, %w", err)
		}

		r.OpaAuthzURL = authzURL
	}

	return nil
}

func (r *Config) isDefaultDenyValid() error {
	if r.EnableDefaultDeny && r.EnableDefaultDenyStrict {
		return errors.New(
			"only one of enable-default-deny/enable-default-deny-strict can be true",
		)
	}
	return nil
}

func (r *Config) updateDiscoveryURI() error {
	// step: fix up the url if required, the underlining lib will add
	// the .well-known/openid-configuration to the discovery url for us.
	r.DiscoveryURL = strings.TrimSuffix(
		r.DiscoveryURL,
		"/.well-known/openid-configuration",
	)

	uri, err := url.ParseRequestURI(r.DiscoveryURL)

	if err != nil {
		return fmt.Errorf(
			"failed to parse discovery url: %w",
			err,
		)
	}

	r.DiscoveryURI = uri

	return nil
}

func (r *Config) extractDiscoveryURIComponents() error {
	reg := regexp.MustCompile(
		`(?P<legacy>(/auth){0,1})/realms/(?P<realm>[^/]+)(/{0,1}).*`,
	)

	matches := reg.FindStringSubmatch(r.DiscoveryURI.Path)

	if len(matches) == 0 {
		return apperrors.ErrBadDiscoveryURIFormat
	}

	legacyIndex := reg.SubexpIndex("legacy")
	realmIndex := reg.SubexpIndex("realm")

	if matches[legacyIndex] != "" {
		r.IsDiscoverURILegacy = true
	}

	r.Realm = matches[realmIndex]
	return nil
}

func (r *Config) isPKCEValid() error {
	if r.NoRedirects && r.EnablePKCE {
		return apperrors.ErrPKCEWithCodeOnly
	}
	return nil
}
