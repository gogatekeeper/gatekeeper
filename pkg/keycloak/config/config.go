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
	redis "github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v2"
)

var _ core.Configs = &Config{}

//nolint:tagalign,lll
type Config struct {
	CommonConfig                       core.CommonConfig
	Scopes                             []string                  `json:"scopes" usage:"list of scopes requested when authenticating the user" yaml:"scopes"`
	Resources                          []*authorization.Resource `json:"resources" usage:"list of resources 'uri=/admin*|methods=GET,PUT|roles=role1,role2'" yaml:"resources"`
	CustomHTTPMethods                  []string                  `json:"custom-http-methods" usage:"list of additional non-standard http methods" yaml:"custom-http-methods"`
	SelfSignedTLSHostnames             []string                  `json:"self-signed-tls-hostnames" usage:"a list of hostnames to place on the self-signed certificate" yaml:"self-signed-tls-hostnames"`
	AddClaims                          []string                  `json:"add-claims" usage:"extra claims from the token and inject into headers, e.g given_name -> X-Auth-Given-Name" yaml:"add-claims"`
	CorsOrigins                        []string                  `json:"cors-origins" usage:"origins to add to the CORE origins control (Access-Control-Allow-Origin)" yaml:"cors-origins"`
	CorsMethods                        []string                  `json:"cors-methods" usage:"methods permitted in the access control (Access-Control-Allow-Methods)" yaml:"cors-methods"`
	CorsHeaders                        []string                  `json:"cors-headers" usage:"set of headers to add to the CORS access control (Access-Control-Allow-Headers)" yaml:"cors-headers"`
	CorsExposedHeaders                 []string                  `json:"cors-exposed-headers" usage:"expose cors headers access control (Access-Control-Expose-Headers)" yaml:"cors-exposed-headers"`
	Hostnames                          []string                  `json:"hostnames" usage:"list of hostnames the service will respond to" yaml:"hostnames"`
	ForwardingDomains                  []string                  `json:"forwarding-domains" usage:"list of domains which should be signed; everything else is relayed unsigned" yaml:"forwarding-domains"`
	ConfigFile                         string                    `env:"CONFIG_FILE" json:"config" usage:"path the a configuration file" yaml:"config"`
	Listen                             string                    `env:"LISTEN" json:"listen" usage:"Defines the binding interface for main listener, e.g. {address}:{port}. This is required and there is no default value" yaml:"listen"`
	ListenHTTP                         string                    `env:"LISTEN_HTTP" json:"listen-http" usage:"interface we should be listening to for HTTP traffic" yaml:"listen-http"`
	ListenAdmin                        string                    `env:"LISTEN_ADMIN" json:"listen-admin" usage:"defines the interface to bind admin-only endpoint (live-status, debug, prometheus...). If not defined, this defaults to the main listener defined by Listen" yaml:"listen-admin"`
	ListenAdminScheme                  string                    `env:"LISTEN_ADMIN_SCHEME" json:"listen-admin-scheme" usage:"scheme to serve admin-only endpoint (http or https)." yaml:"listen-admin-scheme"`
	DiscoveryURL                       string                    `env:"DISCOVERY_URL" json:"discovery-url" usage:"discovery url to retrieve the openid configuration" yaml:"discovery-url"`
	ClientID                           string                    `env:"CLIENT_ID" json:"client-id" usage:"client id used to authenticate to the oauth service" yaml:"client-id"`
	ClientSecret                       string                    `env:"CLIENT_SECRET" json:"client-secret" usage:"client secret used to authenticate to the oauth service" yaml:"client-secret"`
	RedirectionURL                     string                    `env:"REDIRECTION_URL" json:"redirection-url" usage:"redirection url for the oauth callback url, defaults to host header if absent" yaml:"redirection-url"`
	PostLogoutRedirectURI              string                    `env:"POST_LOGOUT_REDIRECT_URI" json:"post-logout-redirect-uri" usage:"url to which client is redirected after successful logout" yaml:"post-logout-redirect-uri"`
	PostLoginRedirectPath              string                    `env:"POST_LOGIN_REDIRECT_PATH" json:"post-login-redirect-path" usage:"path to which client is redirected after successful login, in case user access /" yaml:"post-login-redirect-path"`
	RevocationEndpoint                 string                    `env:"REVOCATION_URL" json:"revocation-url" usage:"url for the revocation endpoint to revoke refresh token" yaml:"revocation-url"`
	OpenIDProviderProxy                string                    `env:"OPENID_PROVIDER_PROXY" json:"openid-provider-proxy" usage:"proxy for communication with the openid provider" yaml:"openid-provider-proxy"`
	UpstreamProxy                      string                    `env:"UPSTREAM_PROXY" json:"upstream-proxy" usage:"proxy for communication with upstream" yaml:"upstream-proxy"`
	UpstreamNoProxy                    string                    `env:"UPSTREAM_NO_PROXY" json:"upstream-no-proxy" usage:"list of upstream destinations which should be not proxied" yaml:"upstream-no-proxy"`
	BaseURI                            string                    `env:"BASE_URI" json:"base-uri" usage:"common prefix for all URIs" yaml:"base-uri"`
	OAuthURI                           string                    `env:"OAUTH_URI" json:"oauth-uri" usage:"the uri for proxy oauth endpoints" yaml:"oauth-uri"`
	Upstream                           string                    `env:"UPSTREAM_URL" json:"upstream-url" usage:"url for the upstream endpoint you wish to proxy" yaml:"upstream-url"`
	UpstreamCA                         string                    `env:"UPSTREAM_CA" json:"upstream-ca" usage:"the path to a file container a CA certificate to validate the upstream tls endpoint" yaml:"upstream-ca"`
	RequestIDHeader                    string                    `env:"REQUEST_ID_HEADER" json:"request-id-header" usage:"the http header name for request id" yaml:"request-id-header"`
	ContentSecurityPolicy              string                    `env:"CONTENT_SECURITY_POLICY" json:"content-security-policy" usage:"specify the content security policy" yaml:"content-security-policy"`
	OpaAuthzURI                        string                    `env:"OPA_AUTHZ_URI"            json:"opa-authz-uri"            usage:"OPA endpoint address with path"                                                                      yaml:"opa-authz-uri"`
	CookieDomain                       string                    `env:"COOKIE_DOMAIN" json:"cookie-domain" usage:"domain the access cookie is available to, defaults host header" yaml:"cookie-domain"`
	CookiePath                         string                    `env:"COOKIE_PATH" json:"cookie-path" usage:"path for which cookie is valid" yaml:"cookie-path"`
	CookieAccessName                   string                    `env:"COOKIE_ACCESS_NAME" json:"cookie-access-name" usage:"name of the cookie used to hold the access token" yaml:"cookie-access-name"`
	CookieIDTokenName                  string                    `env:"COOKIE_ID_TOKEN_NAME" json:"cookie-id-token-name" usage:"name of the cookie used to hold id token" yaml:"cookie-id-token-name"`
	CookieRefreshName                  string                    `env:"COOKIE_REFRESH_NAME" json:"cookie-refresh-name" usage:"name of the cookie used to hold the encrypted refresh token" yaml:"cookie-refresh-name"`
	CookieOAuthStateName               string                    `env:"COOKIE_OAUTH_STATE_NAME" json:"cookie-oauth-state-name" usage:"name of the cookie used to hold the Oauth request state" yaml:"cookie-oauth-state-name"`
	CookieRequestURIName               string                    `env:"COOKIE_REQUEST_URI_NAME" json:"cookie-request-uri-name" usage:"name of the cookie used to hold the request uri" yaml:"cookie-request-uri-name"`
	CookiePKCEName                     string                    `env:"COOKIE_PKCE_NAME" json:"cookie-pkce-name" usage:"name of the cookie used to hold PKCE code verifier" yaml:"cookie-pkce-name"`
	CookieUMAName                      string                    `env:"COOKIE_UMA_NAME" json:"cookie-uma-name" usage:"name of the cookie used to hold the UMA RPT token" yaml:"cookie-uma-name"`
	SameSiteCookie                     string                    `env:"SAME_SITE_COOKIE" json:"same-site-cookie" usage:"enforces cookies to be send only to same site requests according to the policy (can be Strict|Lax|None)" yaml:"same-site-cookie"`
	TLSCertificate                     string                    `env:"TLS_CERTIFICATE" json:"tls-cert" usage:"path to the TLS certificate" yaml:"tls-cert"`
	TLSPrivateKey                      string                    `env:"TLS_PRIVATE_KEY" json:"tls-private-key" usage:"path to the private key for TLS" yaml:"tls-private-key"`
	TLSClientCertificate               string                    `env:"TLS_CLIENT_CERTIFICATE" json:"tls-client-certificate" usage:"path to the client certificate used for authenticating to upstream" yaml:"tls-client-certificate"`
	TLSClientPrivateKey                string                    `env:"TLS_CLIENT_PRIVATE_KEY" json:"tls-client-private-key" usage:"path to the client private key, used for authentication to upstream" yaml:"tls-client-private-key"`
	TLSClientCACertificate             string                    `env:"TLS_CLIENT_CA_CERTIFICATE" json:"tls-client-ca-certificate" usage:"path to the client CA certificate, used for verifying client certificates" yaml:"tls-client-ca-certificate"`
	TLSForwardingCACertificate         string                    `env:"TLS_FORWARDING_CA_CERTIFICATE" json:"tls-forwarding-ca-certificate" usage:"path to the CA certificate, used for generating server cert for forwarding-proxy" yaml:"tls-forwarding-ca-certificate"`
	TLSForwardingCAPrivateKey          string                    `env:"TLS_FORWARDING_CA_PRIVATE_KEY" json:"tls-forwarding-ca-private-key" usage:"path to the CA private key, used for generating server cert for forwarding proxy" yaml:"tls-forwarding-ca-private-key"`
	TLSMinVersion                      string                    `env:"TLS_MIN_VERSION" json:"tls-min-version" usage:"specify server minimal TLS version one of tlsv1.2,tlsv1.3" yaml:"tls-min-version"`
	TLSAdminCertificate                string                    `env:"TLS_ADMIN_CERTIFICATE" json:"tls-admin-cert" usage:"path to the TLS certificate" yaml:"tls-admin-cert"`
	TLSAdminPrivateKey                 string                    `env:"TLS_ADMIN_PRIVATE_KEY" json:"tls-admin-private-key" usage:"path to the private key for TLS" yaml:"tls-admin-private-key"`
	TLSAdminClientCACertificate        string                    `env:"TLS_ADMIN_CLIENT_CA_CERTIFICATE" json:"tls-admin-client-ca-certificate" usage:"path to the client CA certificate user for verifying client certificates" yaml:"tls-admin-client-certificate"`
	TLSStoreCACertificate              string                    `env:"TLS_STORE_CA_CERTIFICATE" json:"tls-store-ca-certificate" usage:"path to the ca certificate used for verifying trusted server certificates" yaml:"tls-store-ca-certificate"`
	TLSStoreClientCertificate          string                    `env:"TLS_STORE_CLIENT_CERTIFICATE" json:"tls-store-client-certificate" usage:"path to the client certificate, used for authenticating to store" yaml:"tls-store-client-certificate"`
	TLSStoreClientPrivateKey           string                    `env:"TLS_STORE_CLIENT_PRIVATE_KEY" json:"tls-store-client-private-key" usage:"path to the client private key, used for authenticating to store" yaml:"tls-store-client-private-key"`
	StoreURL                           string                    `env:"STORE_URL" json:"store-url" usage:"url for the storage subsystem, e.g redis://user:secret@localhost:6379/0?protocol=3, only supported is redis usig redis uri spec" yaml:"store-url"`
	EncryptionKey                      string                    `env:"ENCRYPTION_KEY" json:"encryption-key" usage:"encryption key used to encryption the session state" yaml:"encryption-key"`
	LetsEncryptCacheDir                string                    `env:"LETS_ENCRYPT_CACHE_DIR" json:"letsencrypt-cache-dir" usage:"path where cached letsencrypt certificates are stored" yaml:"letsencrypt-cache-dir"`
	SignInPage                         string                    `env:"SIGN_IN_PAGE" json:"sign-in-page" usage:"path to custom template displayed for signin" yaml:"sign-in-page"`
	RegisterPage                       string                    `env:"REGISTER_PAGE" json:"register-page" usage:"path to custom template displayed for registration" yaml:"register-page"`
	ForbiddenPage                      string                    `env:"FORBIDDEN_PAGE" json:"forbidden-page" usage:"path to custom template used for access forbidden" yaml:"forbidden-page"`
	ErrorPage                          string                    `env:"ERROR_PAGE" json:"error-page" usage:"path to custom template displayed for http.StatusBadRequest" yaml:"error-page"`
	ForwardingGrantType                string                    `env:"FORWARDING_GRANT_TYPE" json:"forwarding-grant-type" usage:"grant-type to use when logging into the openid provider, can be one of password, client_credentials" yaml:"forwarding-grant-type"`
	ForwardingUsername                 string                    `env:"FORWARDING_USERNAME" json:"forwarding-username" usage:"username to use when logging into the openid provider" yaml:"forwarding-username"`
	ForwardingPassword                 string                    `env:"FORWARDING_PASSWORD" json:"forwarding-password" usage:"password to use when logging into the openid provider" yaml:"forwarding-password"`
	Realm                              string
	TLSOpenIDProviderCACertificate     string            `env:"TLS_OPENID_PROVIDER_CA_CERTIFICATE" json:"tls-openid-provider-ca-certificate" usage:"path to the ca certificate for IDP" yaml:"tls-openid-provider-ca-certificate"`
	TLSOpenIDProviderClientPrivateKey  string            `env:"TLS_OPENID_PROVIDER_CLIENT_PRIVATE_KEY" json:"tls-openid-provider-client-private-key" usage:"path to the client private key for IDP" yaml:"tls-openid-provider-client-private-key"`
	TLSOpenIDProviderClientCertificate string            `env:"TLS_OPENID_PROVIDER_CLIENT_CERTIFICATE" json:"tls-openid-provider-client-certificate" usage:"path to the client certificate for IDP" yaml:"tls-openid-provider-client-certificate"`
	OpenIDProviderTimeout              time.Duration     `env:"OPENID_PROVIDER_TIMEOUT" json:"openid-provider-timeout" usage:"timeout for openid configuration on .well-known/openid-configuration" yaml:"openid-provider-timeout"`
	OpenIDProviderRetryCount           int               `env:"OPENID_PROVIDER_RETRY_COUNT" json:"openid-provider-retry-count" usage:"number of retries for retrieving openid configuration" yaml:"openid-provider-retry-count"`
	OpenIDProviderHeaders              map[string]string `json:"openid-provider-headers" usage:"http headers sent to idp provider" yaml:"openid-provider-headers"`
	Headers                            map[string]string `json:"headers" usage:"custom headers to the upstream request, key=value" yaml:"headers"`
	ResponseHeaders                    map[string]string `json:"response-headers" usage:"custom headers to added to the http response key=value" yaml:"response-headers"`
	AllowedQueryParams                 map[string]string `json:"allowed-query-params" usage:"allowed query params, sent to IDP key=optional value" yaml:"allowed-query-params"`
	DefaultAllowedQueryParams          map[string]string `json:"default-allowed-query-params" usage:"default allowed query params, sent to IDP key=value" yaml:"default-allowed-query-params"`
	SelfSignedTLSExpiration            time.Duration     `env:"SELF_SIGNED_TLS_EXPIRATION" json:"self-signed-tls-expiration" usage:"the expiration of the certificate before rotation" yaml:"self-signed-tls-expiration"`
	OpaTimeout                         time.Duration     `env:"OPA_TIMEOUT"              json:"opa-timeout"              usage:"timeout for connection to OPA"                                                                       yaml:"opa-timeout"`
	PatRetryCount                      int               `env:"PAT_RETRY_COUNT"    json:"pat-retry-count"    usage:"number of retries to get PAT"        yaml:"pat-retry-count"`
	PatRetryInterval                   time.Duration     `env:"PAT_RETRY_INTERVAL" json:"pat-retry-interval" usage:"interval between retries to get PAT" yaml:"pat-retry-interval"`
	AccessTokenDuration                time.Duration     `env:"ACCESS_TOKEN_DURATION" json:"access-token-duration" usage:"fallback cookie duration for the access token when using refresh tokens" yaml:"access-token-duration"`
	MatchClaims                        map[string]string `json:"match-claims" usage:"keypair values for matching access token claims e.g. aud=myapp, iss=http://example.*" yaml:"match-claims"`
	CorsMaxAge                         time.Duration     `env:"CORS_MAX_AGE" json:"cors-max-age" usage:"max age applied to cors headers (Access-Control-Max-Age)" yaml:"cors-max-age"`
	UpstreamTimeout                    time.Duration     `env:"UPSTREAM_TIMEOUT" json:"upstream-timeout" usage:"maximum amount of time a dial will wait for a connect to complete" yaml:"upstream-timeout"`
	UpstreamKeepaliveTimeout           time.Duration     `env:"UPSTREAM_KEEPALIVE_TIMEOUT" json:"upstream-keepalive-timeout" usage:"specifies the keep-alive period for an active network connection" yaml:"upstream-keepalive-timeout"`
	UpstreamTLSHandshakeTimeout        time.Duration     `env:"UPSTREAM_TLS_HANDSHAKE_TIMEOUT" json:"upstream-tls-handshake-timeout" usage:"the timeout placed on the tls handshake for upstream" yaml:"upstream-tls-handshake-timeout"`
	UpstreamResponseHeaderTimeout      time.Duration     `env:"UPSTREAM_RESPONSE_HEADER_TIMEOUT" json:"upstream-response-header-timeout" usage:"the timeout placed on the response header for upstream" yaml:"upstream-response-header-timeout"`
	UpstreamExpectContinueTimeout      time.Duration     `env:"UPSTREAM_EXPECT_CONTINUE_TIMEOUT" json:"upstream-expect-continue-timeout" usage:"the timeout placed on the expect continue for upstream" yaml:"upstream-expect-continue-timeout"`
	MaxIdleConns                       int               `env:"MAX_IDLE_CONNS" json:"max-idle-connections" usage:"max idle upstream / keycloak connections to keep alive, ready for reuse" yaml:"max-idle-connections"`
	MaxIdleConnsPerHost                int               `env:"MAX_IDLE_CONNS_PER_HOST" json:"max-idle-connections-per-host" usage:"limits the number of idle connections maintained per host" yaml:"max-idle-connections-per-host"`
	ServerGraceTimeout                 time.Duration     `env:"SERVER_GRACE_TIMEOUT" json:"server-grace-timeout" usage:"the server wait before closing the server" yaml:"server-grace-timeout"`
	ServerReadTimeout                  time.Duration     `env:"SERVER_READ_TIMEOUT" json:"server-read-timeout" usage:"the server read timeout on the http server" yaml:"server-read-timeout"`
	ServerWriteTimeout                 time.Duration     `env:"SERVER_WRITE_TIMEOUT" json:"server-write-timeout" usage:"the server write timeout on the http server" yaml:"server-write-timeout"`
	ServerIdleTimeout                  time.Duration     `env:"SERVER_IDLE_TIMEOUT" json:"server-idle-timeout" usage:"the server idle timeout on the http server" yaml:"server-idle-timeout"`
	Tags                               map[string]string `json:"tags" usage:"keypairs passed to the templates at render,e.g title=Page" yaml:"tags"`
	DiscoveryURI                       *url.URL
	OpaAuthzURL                        *url.URL
	SkipOpenIDProviderTLSVerify        bool `env:"SKIP_OPENID_PROVIDER_TLSVERIFY" json:"skip-openid-provider-tls-verify" usage:"skip the verification of any TLS communication with the openid provider" yaml:"skip-openid-provider-tls-verify"`
	PreserveHost                       bool `env:"PRESERVE_HOST" json:"preserve-host" usage:"preserve the host header of the proxied request in the upstream request" yaml:"preserve-host"`
	EnabledSelfSignedTLS               bool `env:"ENABLE_SELF_SIGNED_TLS" json:"enable-self-signed-tls" usage:"create self signed certificates for the proxy" yaml:"enable-self-signed-tls"`
	EnableRequestID                    bool `env:"ENABLE_REQUEST_ID" json:"enable-request-id" usage:"indicates we should add a request id if none found" yaml:"enable-request-id"`
	EnableLogoutRedirect               bool `env:"ENABLE_LOGOUT_REDIRECT" json:"enable-logout-redirect" usage:"indicates we should redirect to the identity provider for logging out" yaml:"enable-logout-redirect"`
	EnableDefaultDeny                  bool `env:"ENABLE_DEFAULT_DENY" json:"enable-default-deny" usage:"enables a default denial on all unauthenticated requests, you have to explicitly say what is permitted, although be aware that it allows any valid token" yaml:"enable-default-deny"`
	EnableDefaultDenyStrict            bool `env:"ENABLE_DEFAULT_DENY_STRICT" json:"enable-default-deny-strict" usage:"enables a default denial on all requests, even valid token is denied unless you create some resources" yaml:"enable-default-deny-strict"`
	EnableEncryptedToken               bool `env:"ENABLE_ENCRYPTED_TOKEN" json:"enable-encrypted-token" usage:"enable encryption for the access tokens" yaml:"enable-encrypted-token"`
	ForceEncryptedCookie               bool `env:"FORCE_ENCRYPTED_COOKIE" json:"force-encrypted-cookie" usage:"force encryption for the access tokens in cookies" yaml:"force-encrypted-cookie"`
	EnableLogging                      bool `env:"ENABLE_LOGGING" json:"enable-logging" usage:"enable http logging of the requests" yaml:"enable-logging"`
	EnableJSONLogging                  bool `env:"ENABLE_JSON_LOGGING" json:"enable-json-logging" usage:"switch on json logging rather than text" yaml:"enable-json-logging"`
	EnableForwarding                   bool `env:"ENABLE_FORWARDING" json:"enable-forwarding" usage:"enables the forwarding proxy mode, signing outbound request" yaml:"enable-forwarding"`
	EnableSecurityFilter               bool `env:"ENABLE_SECURITY_FILTER" json:"enable-security-filter" usage:"enables the security filter handler" yaml:"enable-security-filter"`
	EnableRefreshTokens                bool `env:"ENABLE_REFRESH_TOKEN" json:"enable-refresh-tokens" usage:"enables the handling of the refresh tokens" yaml:"enable-refresh-tokens"`
	EnableSessionCookies               bool `env:"ENABLE_SESSION_COOKIES" json:"enable-session-cookies" usage:"access and refresh tokens are session only i.e. removed browser close" yaml:"enable-session-cookies"`
	EnableLoginHandler                 bool `env:"ENABLE_LOGIN_HANDLER" json:"enable-login-handler" usage:"enables the handling of the refresh tokens" yaml:"enable-login-handler"`
	EnableRegisterHandler              bool `env:"ENABLE_REGISTER_HANDLER" json:"enable-register-handler" usage:"enables the register handler" yaml:"enable-register-handler"`
	EnableTokenHeader                  bool `env:"ENABLE_TOKEN_HEADER" json:"enable-token-header" usage:"enables the token authentication header X-Auth-Token to upstream" yaml:"enable-token-header"`
	EnableAuthorizationHeader          bool `env:"ENABLE_AUTHORIZATION_HEADER" json:"enable-authorization-header" usage:"adds the authorization header to the proxy request" yaml:"enable-authorization-header"`
	EnableHeaderEncoding               bool `env:"ENABLE_HEADER_ENCODING" json:"enable-header-encoding" usage:"encodes header values according RFC 2047, in MIME B format" yaml:"enable-header-encoding"`
	EnableAuthorizationCookies         bool `env:"ENABLE_AUTHORIZATION_COOKIES" json:"enable-authorization-cookies" usage:"adds the authorization cookies to the uptream proxy request" yaml:"enable-authorization-cookies"`
	EnableHTTPSRedirect                bool `env:"ENABLE_HTTPS_REDIRECT" json:"enable-https-redirection" usage:"enable the http to https redirection on the http service" yaml:"enable-https-redirection"`
	EnableProfiling                    bool `env:"ENABLE_PROFILING" json:"enable-profiling" usage:"switching on the golang profiling via pprof on /debug/pprof, /debug/pprof/heap etc" yaml:"enable-profiling"`
	EnableMetrics                      bool `env:"ENABLE_METRICS" json:"enable-metrics" usage:"enable the prometheus metrics collector on /oauth/metrics" yaml:"enable-metrics"`
	EnableBrowserXSSFilter             bool `env:"ENABLE_BROWSER_XSS_FILTER" json:"filter-browser-xss" usage:"enable the adds the X-XSS-Protection header with mode=block" yaml:"filter-browser-xss"`
	EnableContentNoSniff               bool `env:"ENABLE_CONTENT_NO_SNIFF" json:"filter-content-nosniff" usage:"adds the X-Content-Type-Options header with the value nosniff" yaml:"filter-content-nosniff"`
	EnableFrameDeny                    bool `env:"ENABLE_FRAME_DENY" json:"filter-frame-deny" usage:"enable to the frame deny header" yaml:"filter-frame-deny"`
	LocalhostMetrics                   bool `env:"LOCALHOST_METRICS" json:"localhost-metrics" usage:"enforces the metrics page can only been requested from 127.0.0.1" yaml:"localhost-metrics"`
	EnableCompression                  bool `env:"ENABLE_COMPRESSION" json:"enable-compression" usage:"enable gzip compression for response" yaml:"enable-compression"`
	EnablePKCE                         bool `env:"ENABLE_PKCE"              json:"enable-pkce"              usage:"enable pkce for auth code flow, only S256 code challenge supported"                                  yaml:"enable-pkce"`
	EnableIDPSessionCheck              bool `env:"ENABLE_IDP_SESSION_CHECK" json:"enable_idp_session_check" usage:"during token validation it also checks if user session is still present, useful for multiapp logout" yaml:"enable-idp-session-check"`
	EnableUma                          bool `env:"ENABLE_UMA"               json:"enable-uma"               usage:"enable uma authorization, please don't use it in production, we would like to receive feedback"      yaml:"enable-uma"`
	EnableOpa                          bool `env:"ENABLE_OPA"               json:"enable-opa"               usage:"enable authorization with external Open policy agent"                                                yaml:"enable-opa"`
	SecureCookie                       bool `env:"SECURE_COOKIE" json:"secure-cookie" usage:"enforces the cookie to be secure" yaml:"secure-cookie"`
	HTTPOnlyCookie                     bool `env:"HTTP_ONLY_COOKIE" json:"http-only-cookie" usage:"enforces the cookie is in http only mode" yaml:"http-only-cookie"`
	EnableIDTokenCookie                bool `env:"ENABLE_IDTOKEN_COOKIE" json:"enable-id-token-cookie" usage:"enable id token cookie" yaml:"enable-id-token-cookie"`
	EnableUmaMethodScope               bool `env:"ENABLE_UMA_METHOD_SCOPE" json:"enable-uma-method-scope" usage:"enables passing request method as 'method:GET' scope to keycloak for authorization" yaml:"enable-uma-method-scope"`
	SkipUpstreamTLSVerify              bool `env:"SKIP_UPSTREAM_TLS_VERIFY" json:"skip-upstream-tls-verify" usage:"skip the verification of any upstream TLS" yaml:"skip-upstream-tls-verify"`
	CorsCredentials                    bool `env:"CORS_CREDENTIALS" json:"cors-credentials" usage:"credentials access control header (Access-Control-Allow-Credentials)" yaml:"cors-credentials"`
	EnableHmac                         bool `env:"ENABLE_HMAC" json:"enable-hmac" usage:"enable creating hmac for forwarded requests and verification on incoming requests" yaml:"enable-hmac"`
	NoProxy                            bool `env:"NO_PROXY" json:"no-proxy" usage:"do not proxy requests to upstream, useful for forward-auth usage (with nginx, traefik)" yaml:"no-proxy"`
	NoRedirects                        bool `env:"NO_REDIRECTS" json:"no-redirects" usage:"do not have back redirects when no authentication is present, 401 them" yaml:"no-redirects"`
	SkipAccessTokenIssuerCheck         bool `env:"SKIP_ACCESS_TOKEN_ISSUER_CHECK" json:"skip-access-token-issuer-check" usage:"according RFC issuer should not be checked on access token, this will be default true in future" yaml:"skip-access-token-issuer-check"`
	SkipAccessTokenClientIDCheck       bool `env:"SKIP_ACCESS_TOKEN_CLIENT_ID_CHECK" json:"skip-access-token-clientid-check" usage:"according RFC client id should not be checked on access token, this will be default true in future" yaml:"skip-access-token-clientid-check"`
	SkipAuthorizationHeaderIdentity    bool `env:"SKIP_AUTHORIZATION_HEADER_IDENTITY" json:"skip-authorization-header-identity" usage:"skip authorization header identity, means that we won't be extracting token from authorization header (e.g. if authorization header is used only by application behind gatekeeper)" yaml:"skip-authorization-header-identity"`
	UpstreamKeepalives                 bool `env:"UPSTREAM_KEEPALIVES" json:"upstream-keepalives" usage:"enables or disables the keepalive connections for upstream endpoint" yaml:"upstream-keepalives"`
	Verbose                            bool `env:"VERBOSE" json:"verbose" usage:"switch on debug / verbose logging" yaml:"verbose"`
	EnableProxyProtocol                bool `env:"ENABLE_PROXY_PROTOCOL" json:"enabled-proxy-protocol" usage:"enable proxy protocol" yaml:"enabled-proxy-protocol"`
	UseLetsEncrypt                     bool `env:"USE_LETS_ENCRYPT" json:"use-letsencrypt" usage:"use letsencrypt for certificates" yaml:"use-letsencrypt"`
	DisableAllLogging                  bool `env:"DISABLE_ALL_LOGGING" json:"disable-all-logging" usage:"disables all logging to stdout and stderr" yaml:"disable-all-logging"`
	EnableLoA                          bool `env:"ENABLE_LOA" json:"enable-loa" usage:"enables level of authentication" yaml:"enable-loa"`
	EnableStoreHA                      bool `env:"ENABLE_STORE_HA" json:"enable-store-ha" usage:"enable store high availability client, currently only redis-cluster supported" yaml:"enable-store-ha"`
	EnableSigning                      bool `env:"ENABLE_SIGNING" json:"enable-signing" usage:"enable signing of requests to upstream, when in reverse proxy mode" yaml:"enable-signing"`
	EnableSigningHmac                  bool `env:"ENABLE_SIGNING_HMAC" json:"enable-signing-hmac" usage:"enable signing of requests to upstream, when in reverse proxy mode with HMAC" yaml:"enable-signing-hmac"`
	EnableXForwardedHeaders            bool `env:"ENABLE_X_FORWARDED_HEADERS" json:"enable-x-forwarded-headers" usage:"enable using X-Forwarded headers (host and proto) for callback and authorization url" yaml:"enable-x-forwarded-headers"`
	EnableOptionalEncryption           bool `env:"ENABLE_OPTIONAL_ENCRYPTION" json:"enable-optional-encryption" usage:"enable optional decryption for access tokens, id tokens, refresh tokens" yaml:"enable-optional-encryption"`
	EnableLogoutAuth                   bool `env:"ENABLE_LOGOUT_AUTH" json:"enable-logout-auth" usage:"enable authentication on logout handler" yaml:"enable-logout-auth"`
	EnableRequestUpstreamCompression   bool `env:"ENABLE_REQUEST_UPSTREAM_COMPRESSION" json:"enable-request-upstream-compression" usage:"enables asking upstream for compression, by adding Accept-Encoding: gzip header and decompressing response from upstream" yaml:"enable-request-upstream-compression"`
	IsDiscoverURILegacy                bool
}

func NewDefaultConfig() *Config {
	var hostnames []string
	if name, err := os.Hostname(); err == nil {
		hostnames = append(hostnames, name)
	}
	hostnames = append(hostnames, []string{"localhost", "127.0.0.1", "::1"}...)

	return &Config{
		AccessTokenDuration:              time.Duration(constant.FallbackAccessTokenDuration) * time.Hour,
		CookieAccessName:                 constant.AccessCookie,
		CookieIDTokenName:                constant.IDTokenCookie,
		CookieRefreshName:                constant.RefreshCookie,
		CookieOAuthStateName:             constant.RequestStateCookie,
		CookieRequestURIName:             constant.RequestURICookie,
		CookiePKCEName:                   constant.PKCECookie,
		EnableAuthorizationCookies:       true,
		EnableAuthorizationHeader:        true,
		EnableDefaultDeny:                true,
		EnableSessionCookies:             true,
		EnableTokenHeader:                true,
		EnableJSONLogging:                true,
		EnableEncryptedToken:             true,
		EnablePKCE:                       true,
		EnableLogoutAuth:                 true,
		EnableRequestUpstreamCompression: true,
		HTTPOnlyCookie:                   true,
		Headers:                          make(map[string]string),
		AllowedQueryParams:               make(map[string]string),
		DefaultAllowedQueryParams:        make(map[string]string),
		LetsEncryptCacheDir:              "./cache/",
		MatchClaims:                      make(map[string]string),
		MaxIdleConns:                     constant.DefaultMaxIdleConns,
		MaxIdleConnsPerHost:              constant.DefaultMaxIdleConnsPerHost,
		OAuthURI:                         "/oauth",
		OpenIDProviderTimeout:            constant.DefaultOpenIDProviderTimeout,
		OpenIDProviderRetryCount:         constant.DefaultOpenIDProviderRetryCount,
		PreserveHost:                     false,
		SelfSignedTLSExpiration:          constant.DefaultSelfSignedTLSExpiration,
		SelfSignedTLSHostnames:           hostnames,
		RequestIDHeader:                  "X-Request-ID",
		ResponseHeaders:                  make(map[string]string),
		SameSiteCookie:                   constant.SameSiteLax,
		Scopes:                           []string{"email", "profile"},
		SecureCookie:                     true,
		ServerGraceTimeout:               constant.DefaultServerGraceTimeout,
		ServerIdleTimeout:                constant.DefaultServerIdleTimeout,
		ServerReadTimeout:                constant.DefaultServerReadTimeout,
		ServerWriteTimeout:               constant.DefaultServerWriteTimeout,
		SkipOpenIDProviderTLSVerify:      false,
		SkipUpstreamTLSVerify:            false,
		SkipAccessTokenIssuerCheck:       true,
		SkipAccessTokenClientIDCheck:     true,
		Tags:                             make(map[string]string),
		TLSMinVersion:                    constant.TLS13,
		UpstreamExpectContinueTimeout:    constant.DefaultUpstreamExpectContinueTimeout,
		UpstreamKeepaliveTimeout:         constant.DefaultUpstreamKeepaliveTimeout,
		UpstreamKeepalives:               true,
		UpstreamResponseHeaderTimeout:    constant.DefaultUpstreamResponseHeaderTimeout,
		UpstreamTLSHandshakeTimeout:      constant.DefaultUpstreamTLSHandshakeTimeout,
		UpstreamTimeout:                  constant.DefaultUpstreamTimeout,
		UseLetsEncrypt:                   false,
		ForwardingGrantType:              core.GrantTypeUserCreds,
		PatRetryCount:                    constant.DefaultPatRetryCount,
		PatRetryInterval:                 constant.DefaultPatRetryInterval,
		OpaTimeout:                       constant.DefaultOpaTimeout,
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

// readConfigFile reads and parses the configuration file.
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

// IsValid validates if the config is valid.
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
		r.isCorsValid,
		r.isTLSFilesValid,
		r.isAdminTLSFilesValid,
		r.isLetsEncryptValid,
		r.isTLSMinValid,
		r.isUpstreamProxyValid,
		r.isEnableRequestUpstreamCompressionValid,
		r.isForwardingProxySettingsValid,
		r.isReverseProxySettingsValid,
		r.isCookieValid,
	}

	for _, validationFunc := range validationRegistry {
		if err := validationFunc(); err != nil {
			return err
		}
	}

	return nil
}

func (r *Config) HasCustomSignInPage() bool {
	return r.SignInPage != ""
}

func (r *Config) HasCustomForbiddenPage() bool {
	return r.ForbiddenPage != ""
}

func (r *Config) HasCustomErrorPage() bool {
	return r.ErrorPage != ""
}

func (r *Config) isListenValid() error {
	if r.Listen == "" {
		return apperrors.ErrMissingListenInterface
	}
	return nil
}

func (r *Config) isListenAdminSchemeValid() error {
	if r.ListenAdminScheme != constant.SecureScheme &&
		r.ListenAdminScheme != constant.UnsecureScheme {
		return apperrors.ErrAdminListenerScheme
	}
	return nil
}

func (r *Config) isOpenIDProviderProxyValid() error {
	if r.TLSOpenIDProviderCACertificate != "" && r.SkipOpenIDProviderTLSVerify {
		return apperrors.ErrIDPCAandSkipTLS
	}

	if r.OpenIDProviderProxy != "" {
		_, err := url.ParseRequestURI(r.OpenIDProviderProxy)
		if err != nil {
			return apperrors.ErrInvalidIdpProviderProxyURI
		}
	}

	return nil
}

func (r *Config) isMaxIdlleConnValid() error {
	if r.MaxIdleConns <= 0 {
		return apperrors.ErrInvalidMaxIdleConnections
	}

	if r.MaxIdleConnsPerHost < 0 || r.MaxIdleConnsPerHost > r.MaxIdleConns {
		return apperrors.ErrInvalidMaxIdleConnsPerHost
	}
	return nil
}

func (r *Config) isSameSiteValid() error {
	if r.SameSiteCookie != "" && r.SameSiteCookie != constant.SameSiteStrict &&
		r.SameSiteCookie != constant.SameSiteLax && r.SameSiteCookie != constant.SameSiteNone {
		return apperrors.ErrInvalidSameSiteCookie
	}
	return nil
}

//nolint:cyclop
func (r *Config) isTLSFilesValid() error {
	if r.TLSCertificate != "" && r.TLSPrivateKey == "" {
		return apperrors.ErrMissingPrivateKey
	}

	if r.TLSPrivateKey != "" && r.TLSCertificate == "" {
		return apperrors.ErrMissingCert
	}

	if r.TLSCertificate != "" && !utils.FileExists(r.TLSCertificate) {
		return apperrors.ErrTLSCertificateNotExists
	}

	if r.TLSPrivateKey != "" && !utils.FileExists(r.TLSPrivateKey) {
		return apperrors.ErrTLSPrivateKeyNotExists
	}

	if r.TLSClientCertificate != "" && !utils.FileExists(r.TLSClientCertificate) {
		return apperrors.ErrTLSClientCertificateNotExists
	}

	if r.TLSClientPrivateKey != "" && !utils.FileExists(r.TLSClientPrivateKey) {
		return apperrors.ErrTLSClientPrivateKeyNotExists
	}

	if r.TLSClientCACertificate != "" && !utils.FileExists(r.TLSClientCACertificate) {
		return apperrors.ErrTLSClientCACertificateNotExists
	}

	if r.TLSForwardingCACertificate != "" && !utils.FileExists(r.TLSForwardingCACertificate) {
		return apperrors.ErrTLSForwardingCACertificateNotExists
	}

	if r.TLSForwardingCAPrivateKey != "" && !utils.FileExists(r.TLSForwardingCAPrivateKey) {
		return apperrors.ErrTLSForwardingCAPrivateKeyNotExists
	}

	if r.TLSStoreCACertificate != "" && !utils.FileExists(r.TLSStoreCACertificate) {
		return apperrors.ErrTLSStoreCACertificateNotExists
	}

	if r.TLSStoreClientCertificate != "" && !utils.FileExists(r.TLSStoreClientCertificate) {
		return apperrors.ErrTLSStoreClientCertificateNotExists
	}

	if r.TLSStoreClientPrivateKey != "" && !utils.FileExists(r.TLSStoreClientPrivateKey) {
		return apperrors.ErrTLSStoreClientPrivateKeyNotExists
	}

	if r.TLSOpenIDProviderCACertificate != "" && !utils.FileExists(r.TLSOpenIDProviderCACertificate) {
		return apperrors.ErrTLSOpenIDPCACertificateNotExists
	}

	if r.TLSOpenIDProviderClientCertificate != "" && !utils.FileExists(r.TLSOpenIDProviderClientCertificate) {
		return apperrors.ErrTLSOpenIDPClientCertificateNotExists
	}

	if r.TLSOpenIDProviderClientPrivateKey != "" && !utils.FileExists(r.TLSOpenIDProviderClientPrivateKey) {
		return apperrors.ErrTLSOpenIDPClientPrivateKeyNotExists
	}

	clientOpenIDPPrivMiss := r.TLSOpenIDProviderClientPrivateKey == "" && r.TLSOpenIDProviderClientCertificate != ""
	clientOpenIDPCertMiss := r.TLSOpenIDProviderClientPrivateKey != "" && r.TLSOpenIDProviderClientCertificate == ""

	if clientOpenIDPPrivMiss || clientOpenIDPCertMiss {
		return apperrors.ErrTLSOpenIDPClientPairMissing
	}

	clientPrivMiss := r.TLSClientPrivateKey == "" && r.TLSClientCertificate != ""
	clientCertMiss := r.TLSClientPrivateKey != "" && r.TLSClientCertificate == ""

	if clientPrivMiss || clientCertMiss {
		return apperrors.ErrTLSClientPairMissing
	}

	forwardingCAPrivMiss := r.TLSForwardingCAPrivateKey == "" && r.TLSForwardingCACertificate != ""
	forwardingCACertMiss := r.TLSForwardingCAPrivateKey != "" && r.TLSForwardingCACertificate == ""

	if forwardingCAPrivMiss || forwardingCACertMiss {
		return apperrors.ErrTLSForwardingCAPairMissing
	}

	storeClientPrivMiss := r.TLSStoreClientPrivateKey == "" && r.TLSStoreClientCertificate != ""
	storeClientCertMiss := r.TLSStoreClientPrivateKey != "" && r.TLSStoreClientCertificate == ""

	if storeClientPrivMiss || storeClientCertMiss {
		return apperrors.ErrTLSStoreClientPairMissing
	}

	return nil
}

//nolint:cyclop
func (r *Config) isAdminTLSFilesValid() error {
	if r.TLSAdminCertificate != "" && r.TLSAdminPrivateKey == "" {
		return apperrors.ErrMissingAdminEndpointPrivateKey
	}

	if r.TLSAdminPrivateKey != "" && r.TLSAdminCertificate == "" {
		return apperrors.ErrMissingAdminEndpointCert
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

	if r.TLSAdminClientCACertificate != "" && !utils.FileExists(r.TLSAdminClientCACertificate) {
		return fmt.Errorf(
			"the tls client CA certificate %s does not exist for admin endpoint",
			r.TLSAdminClientCACertificate,
		)
	}

	return nil
}

func (r *Config) isLetsEncryptValid() error {
	if r.UseLetsEncrypt && r.LetsEncryptCacheDir == "" {
		return apperrors.ErrMissingLetsEncryptCacheDir
	}
	return nil
}

func (r *Config) isTLSMinValid() error {
	switch strings.ToLower(r.TLSMinVersion) {
	case "":
		return apperrors.ErrMinimalTLSVersionEmpty
	case constant.TLS12:
	case constant.TLS13:
	default:
		return apperrors.ErrInvalidMinimalTLSVersion
	}
	return nil
}

func (r *Config) isUpstreamProxyValid() error {
	if r.UpstreamProxy != "" {
		if _, err := url.ParseRequestURI(r.UpstreamProxy); err != nil {
			return fmt.Errorf("the upstream proxy is invalid, %w", err)
		}
	}
	return nil
}

func (r *Config) isForwardingProxySettingsValid() error {
	if r.EnableForwarding {
		validationRegistry := []func() error{
			r.isClientIDValid,
			r.isDiscoveryURLValid,
			r.isForwardingGrantValid,
			r.isEnableHmacValid,
			func() error {
				if r.TLSCertificate != "" {
					return apperrors.ErrInvalidForwardTLSCertOpt
				}
				return nil
			},
			func() error {
				if r.TLSPrivateKey != "" {
					return apperrors.ErrInvalidForwardTLSKeyOpt
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
			r.isPostLoginRedirectValid,
			r.isEnableHmacValid,
			r.isPostLogoutRedirectURIValid,
			r.isAllowedQueryParamsValid,
			r.isEnableLoAValid,
			r.isSigningValid,
			r.isEnableSigningHmacValid,
			r.isEnableXForwardedHeadersValid,
			r.isEnableOptionalEncryptionValid,
			r.isEnableLogoutAuthValid,
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

	return nil
}

func (r *Config) isNoProxyValid() error {
	if r.NoProxy && !r.NoRedirects && r.RedirectionURL != "" {
		return apperrors.ErrRedundantRedirectURIinForwardAuthMode
	}
	return nil
}

func (r *Config) isUpstreamValid() error {
	if r.Upstream == "" && !r.NoProxy {
		return apperrors.ErrMissingUpstream
	}

	if !r.NoProxy {
		if _, err := url.ParseRequestURI(r.Upstream); err != nil {
			return fmt.Errorf("the upstream endpoint is invalid, %w", err)
		}
	}

	if r.SkipUpstreamTLSVerify && r.UpstreamCA != "" {
		return fmt.Errorf("you cannot skip upstream tls and load a root ca: %s to verify it", r.UpstreamCA)
	}

	return nil
}

func (r *Config) isClientIDValid() error {
	if r.ClientID == "" {
		return apperrors.ErrMissingClientID
	}
	return nil
}

func (r *Config) isDiscoveryURLValid() error {
	if r.DiscoveryURL == "" {
		return apperrors.ErrMissingDiscoveryURI
	}
	return nil
}

func (r *Config) isForwardingGrantValid() error {
	if r.ForwardingGrantType == core.GrantTypeUserCreds {
		if r.ForwardingUsername == "" {
			return apperrors.ErrMissingForwardUser
		}
		if r.ForwardingPassword == "" {
			return apperrors.ErrMissingForwardPass
		}
	}

	if r.ForwardingGrantType == core.GrantTypeClientCreds {
		if r.ClientSecret == "" {
			return apperrors.ErrMissingClientSecret
		}
	}

	return nil
}

func (r *Config) isSecurityFilterValid() error {
	if !r.EnableSecurityFilter {
		switch {
		case r.EnableHTTPSRedirect:
			return apperrors.ErrSecFilterDisabledForHTTPSRedirect
		case r.EnableBrowserXSSFilter:
			return apperrors.ErrSecFilterDisabledForXSSFilter
		case r.EnableFrameDeny:
			return apperrors.ErrSecFilterDisabledForFrameDenyFilter
		case r.ContentSecurityPolicy != "":
			return apperrors.ErrSecFilterDisabledForCSPFilter
		case len(r.Hostnames) > 0:
			return apperrors.ErrSecFilterDisabledForHostnames
		default:
			return nil
		}
	}
	return nil
}

func (r *Config) isTokenEncryptionValid() error {
	if (r.EnableEncryptedToken || r.ForceEncryptedCookie) &&
		r.EncryptionKey == "" {
		return apperrors.ErrMissingEncryptionKey
	}

	if r.EnableRefreshTokens && r.EncryptionKey == "" {
		return apperrors.ErrMissingEncryptionKeyForRefreshTokens
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
		return apperrors.ErrSecureCookieWithNonTLSRedirectionURI
	}

	return nil
}

//nolint:cyclop
func (r *Config) isStoreURLValid() error {
	if r.StoreURL != "" {
		hasPlainRedisScheme := strings.HasPrefix(r.StoreURL, constant.RedisScheme+"://")

		if strings.HasPrefix(r.StoreURL, constant.TLSRedisScheme+"://") && r.TLSStoreCACertificate == "" {
			return apperrors.ErrTLSStoreURLCAMissing
		}

		if hasPlainRedisScheme && r.TLSStoreCACertificate != "" {
			return apperrors.ErrCATLSStoreURLMissing
		}

		if hasPlainRedisScheme && r.TLSStoreClientCertificate != "" {
			return apperrors.ErrClientCertTLSStoreURLMissing
		}

		if hasPlainRedisScheme && r.TLSStoreClientPrivateKey != "" {
			return apperrors.ErrClientPrivKeyTLSStoreURLMissing
		}

		if r.EnableStoreHA {
			if _, err := redis.ParseClusterURL(r.StoreURL); err != nil {
				return errors.Join(apperrors.ErrInvalidHAStoreURL, err)
			}
		} else {
			if _, err := redis.ParseURL(r.StoreURL); err != nil {
				return errors.Join(apperrors.ErrInvalidStoreURL, err)
			}
		}
	}

	if r.StoreURL == "" && r.EnableStoreHA {
		return apperrors.ErrMissingStoreURL
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
		return apperrors.ErrTooManyExtAuthzEnabled
	}

	if r.EnableUma {
		if r.ClientID == "" || r.ClientSecret == "" {
			return apperrors.ErrMissingClientCredsWithUMA
		}
		if r.EnableIDPSessionCheck && r.NoRedirects {
			return apperrors.ErrEnableUmaIdpSessionCheckConflict
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
		return apperrors.ErrTooManyDefaultDenyOpts
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

func (r *Config) isPostLoginRedirectValid() error {
	if r.PostLoginRedirectPath != "" && r.NoRedirects {
		return apperrors.ErrPostLoginRedirectPathNoRedirectsInvalid
	}
	if r.PostLoginRedirectPath != "" {
		parsedURI, err := url.ParseRequestURI(r.PostLoginRedirectPath)
		if err != nil {
			return err
		}
		if parsedURI.Host != "" || parsedURI.Scheme != "" {
			return apperrors.ErrInvalidPostLoginRedirectPath
		}
	}
	return nil
}

func (r *Config) isEnableHmacValid() error {
	if r.EnableHmac && r.EncryptionKey == "" {
		return apperrors.ErrHmacRequiresEncKey
	}
	return nil
}

func (r *Config) isPostLogoutRedirectURIValid() error {
	if r.PostLogoutRedirectURI != "" && !r.EnableIDTokenCookie {
		return apperrors.ErrPostLogoutRedirectURIRequiresIDToken
	}
	return nil
}

func (r *Config) isAllowedQueryParamsValid() error {
	if (len(r.AllowedQueryParams) > 0 || len(r.DefaultAllowedQueryParams) > 0) && r.NoRedirects {
		return apperrors.ErrAllowedQueryParamsWithNoRedirects
	}
	if len(r.DefaultAllowedQueryParams) > len(r.AllowedQueryParams) {
		return apperrors.ErrTooManyDefaultAllowedQueryParams
	}
	for k, val := range r.DefaultAllowedQueryParams {
		if val == "" {
			return apperrors.ErrDefaultAllowedQueryParamEmpty
		}
		allowedVal, ok := r.AllowedQueryParams[k]
		if !ok {
			return apperrors.ErrMissingDefaultQueryParamInAllowed
		}
		if allowedVal != "" && val != allowedVal {
			return apperrors.ErrDefaultQueryParamNotAllowed
		}
	}
	return nil
}

func (r *Config) isEnableLoAValid() error {
	if r.EnableLoA && r.NoRedirects {
		return apperrors.ErrLoAWithNoRedirects
	}
	if r.EnableLoA && r.EnableUma {
		return apperrors.ErrLoaWithUMA
	}
	return nil
}

func (r *Config) isCorsValid() error {
	for _, origin := range r.CorsOrigins {
		if origin == "*" && r.CorsCredentials {
			return apperrors.ErrInvalidOriginWithCreds
		}
	}
	return nil
}

func (r *Config) isCookieValid() error {
	if r.CookiePath != "" {
		if !strings.HasPrefix(r.CookiePath, "/") {
			return apperrors.ErrInvalidCookiePath
		}
	}
	return nil
}

func (r *Config) isSigningValid() error {
	if r.EnableSigning && r.NoProxy {
		return apperrors.ErrSigningNoProxy
	}
	if r.EnableSigning && r.EnableForwarding {
		return apperrors.ErrSigningNotWithForwarding
	}
	return nil
}

func (r *Config) isEnableSigningHmacValid() error {
	if r.EnableSigningHmac && r.EncryptionKey == "" {
		return apperrors.ErrSigningHmacMissingEncryptionKey
	}
	return nil
}

func (r *Config) isEnableXForwardedHeadersValid() error {
	if r.EnableXForwardedHeaders && r.RedirectionURL != "" {
		return apperrors.ErrXForwardedRedirectionURL
	}
	return nil
}

func (r *Config) isEnableOptionalEncryptionValid() error {
	if r.EnableOptionalEncryption && !r.EnableEncryptedToken && !r.ForceEncryptedCookie {
		return apperrors.ErrOptionalEncryptionWithNoEncryption
	}
	return nil
}

func (r *Config) isEnableLogoutAuthValid() error {
	if !r.EnableLogoutAuth && !r.EnableLogoutRedirect {
		return apperrors.ErrDisableAuthLogout
	}
	return nil
}

func (r *Config) isEnableRequestUpstreamCompressionValid() error {
	if !r.EnableRequestUpstreamCompression && r.EnableCompression {
		return apperrors.ErrEnableRequestUpstreamCompression
	}
	return nil
}
