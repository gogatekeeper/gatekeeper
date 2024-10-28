package constant

import (
	"time"

	"github.com/go-jose/go-jose/v4"
)

type contextKey int8

const (
	Prog        = "gatekeeper"
	Author      = "go-gatekeeper"
	Email       = ""
	Description = "is a proxy using the keycloak service for auth and authorization"

	AuthorizationHeader = "Authorization"
	AuthorizationType   = "Bearer"
	EnvPrefix           = "PROXY_"
	HeaderUpgrade       = "Upgrade"
	VersionHeader       = "X-Auth-Proxy-Version"
	UMATicketHeader     = "WWW-Authenticate"

	AuthorizationURL = "/authorize"
	CallbackURL      = "/callback"
	ExpiredURL       = "/expired"
	HealthURL        = "/health"
	LoginURL         = "/login"
	LogoutURL        = "/logout"
	MetricsURL       = "/metrics"
	TokenURL         = "/token"
	DebugURL         = "/debug/pprof"
	DiscoveryURL     = "/discovery"

	ClaimResourceRoles = "roles"

	AccessCookie       = "kc-access"
	RefreshCookie      = "kc-state"
	RequestURICookie   = "request_uri"
	RequestStateCookie = "OAuth_Token_Request_State"
	PKCECookie         = "pkce"
	IDTokenCookie      = "id_token"
	UMACookie          = "uma_token"
	// case is like this because go net package canonicalizes it
	// to this form, see net package
	UMAHeader      = "X-Uma-Token"
	UnsecureScheme = "http"
	SecureScheme   = "https"
	AnyMethod      = "ANY"
	UmaMethodScope = "method:"

	_ contextKey = iota
	ContextScopeName
	HeaderXForwardedFor = "X-Forwarded-For"
	HeaderXRealIP       = "X-Real-IP"
	HeaderXHMAC         = "X-HMAC-SHA256"

	DurationType = "time.Duration"

	// SameSite cookie config options
	SameSiteStrict = "Strict"
	SameSiteLax    = "Lax"
	SameSiteNone   = "None"

	AllPath = "/*"

	IdpWellKnownURI   = "/.well-known/openid-configuration"
	IdpCertsURI       = "/protocol/openid-connect/certs"
	IdpTokenURI       = "/protocol/openid-connect/token"
	IdpAuthURI        = "/protocol/openid-connect/auth"
	IdpUserURI        = "/protocol/openid-connect/userinfo"
	IdpLogoutURI      = "/protocol/openid-connect/logout"
	IdpRevokeURI      = "/protocol/openid-connect/revoke"
	IdpResourceSetURI = "/authz/protection/resource_set"
	IdpProtectPermURI = "/authz/protection/permission"

	InvalidCookieDuration   = -10 * time.Hour
	PKCECodeVerifierLength  = 96
	PATRefreshInPercent     = 0.85
	HTTPCompressionLevel    = 5
	SelfSignedRSAKeyLength  = 2048
	SelfSignedMaxSerialBits = 128
	CookiesPerDomainSize    = 4069
	RedisTimeout            = 10 * time.Second

	FallbackAccessTokenDuration          = 720
	DefaultMaxIdleConns                  = 100
	DefaultMaxIdleConnsPerHost           = 50
	DefaultOpenIDProviderTimeout         = 30 * time.Second
	DefaultOpenIDProviderRetryCount      = 3
	DefaultSelfSignedTLSExpiration       = 3 * time.Hour
	DefaultServerGraceTimeout            = 10 * time.Second
	DefaultServerIdleTimeout             = 120 * time.Second
	DefaultServerReadTimeout             = 10 * time.Second
	DefaultServerWriteTimeout            = 10 * time.Second
	DefaultUpstreamExpectContinueTimeout = 10 * time.Second
	DefaultUpstreamKeepaliveTimeout      = 10 * time.Second
	DefaultUpstreamResponseHeaderTimeout = 10 * time.Second
	DefaultUpstreamTLSHandshakeTimeout   = 10 * time.Second
	DefaultUpstreamTimeout               = 10 * time.Second
	DefaultPatRetryCount                 = 5
	DefaultPatRetryInterval              = 10 * time.Second
	DefaultOpaTimeout                    = 10 * time.Second

	ForwardingGrantTypePassword = "password"

	TLS13 = "tlsv1.3"
	TLS12 = "tlsv1.2"
)

var SignatureAlgs = [3]jose.SignatureAlgorithm{jose.RS256, jose.HS256, jose.HS512}
