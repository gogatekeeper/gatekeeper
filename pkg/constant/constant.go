package constant

import (
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
)

type (
	contextKey int8
	AuthScheme string
)

const (
	_ contextKey = iota
	ContextScopeName
)

const (
	Prog        = "gatekeeper"
	Author      = "go-gatekeeper"
	Email       = ""
	Description = "is a proxy using the keycloak service for auth and authorization"

	XHeaderPrefix       = "X-Auth-"
	AuthorizationHeader = "Authorization"
	AuthorizationType   = "Bearer"
	EnvPrefix           = "PROXY_"
	HeaderUpgrade       = "Upgrade"
	VersionHeader       = XHeaderPrefix + "Proxy-Version"
	UMATicketHeader     = "WWW-Authenticate"

	AuthorizationURL = "/authorize"
	RegistrationURL  = "/register"
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
	// UMAHeader case is like this because go net package canonicalizes it
	// to this form, see net package.
	UMAHeader      = "X-Uma-Token"
	TokenHeader    = XHeaderPrefix + "Token"
	UnsecureScheme = "http"
	SecureScheme   = "https"
	AnyMethod      = "ANY"
	UmaMethodScope = "method:"

	HeaderXForwardedFor    = "X-Forwarded-For"
	HeaderXForwardedHost   = "X-Forwarded-Host"
	HeaderXRealIP          = "X-Real-IP"
	HeaderXForwardedProto  = "X-Forwarded-Proto"
	HeaderXForwardedURI    = "X-Forwarded-URI"
	HeaderXForwardedMethod = "X-Forwarded-Method"
	HeaderXHMAC            = "X-HMAC-SHA256"
	HeaderContentType      = "Content-Type"

	DurationType = "time.Duration"

	// SameSiteStrict cookie config options.
	SameSiteStrict = "Strict"
	SameSiteLax    = "Lax"
	SameSiteNone   = "None"

	AllPath = "/*"

	//nolint:gosec
	IdpWellKnownURI    = "/.well-known/openid-configuration"
	IdpCertsURI        = "/protocol/openid-connect/certs"
	IdpTokenURI        = "/protocol/openid-connect/token"
	IdpAuthURI         = "/protocol/openid-connect/auth"
	IdpUserURI         = "/protocol/openid-connect/userinfo"
	IdpLogoutURI       = "/protocol/openid-connect/logout"
	IdpRevokeURI       = "/protocol/openid-connect/revoke"
	IdpResourcesSetURI = "/authz/protection/resource_set"
	IdpResourceSetURI  = "/authz/protection/resource_set/{id}"
	IdpProtectPermURI  = "/authz/protection/permission"
	IdpClientIDURI     = "/clients"

	CompressTokenPoolSize   = 100
	MaxBodyPoolSize         = 100
	InvalidCookieDuration   = -10 * time.Hour
	PKCECodeVerifierLength  = 96
	PATRefreshInPercent     = 0.85
	HTTPCompressionLevel    = 5
	PlainTokenParts         = 3
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
	DefaultMaxHeaderSize                 = 1 << 20
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

	TLSRedisScheme = "rediss"
	RedisScheme    = "redis"

	HTTPStatusHeaderLen = 42
	SwitchProtoHeader   = "HTTP/1.1 101 Switching Protocols"
	CRLF                = "\r\n\r\n"

	Cookie AuthScheme = "cookie"
	Bearer AuthScheme = "bearer"

	NegateRegexChar = "!"

	IdentityHeaderEncoding = "UTF-8"
)

//nolint:gochecknoglobals
var (
	SignatureAlgs = [3]jose.SignatureAlgorithm{jose.RS256, jose.HS256, jose.HS512}
	AuthSchemes   = []AuthScheme{Cookie, Bearer}
)

func GetBaseIdentityHeaderSet() map[string]func(user *models.UserContext) string {
	return map[string]func(user *models.UserContext) string{
		XHeaderPrefix + "Audience": func(user *models.UserContext) string {
			return strings.Join(user.Audiences, ",")
		},
		XHeaderPrefix + "Email": func(user *models.UserContext) string {
			return user.Email
		},
		XHeaderPrefix + "Expiresin": func(user *models.UserContext) string {
			return user.ExpiresAt.String()
		},
		XHeaderPrefix + "Groups": func(user *models.UserContext) string {
			return strings.Join(user.Groups, ",")
		},
		XHeaderPrefix + "Roles": func(user *models.UserContext) string {
			return strings.Join(user.Roles, ",")
		},
		XHeaderPrefix + "Subject": func(user *models.UserContext) string {
			return user.ID
		},
		XHeaderPrefix + "Userid": func(user *models.UserContext) string {
			return user.Name
		},
		XHeaderPrefix + "Username": func(user *models.UserContext) string {
			return user.Name
		},
	}
}
