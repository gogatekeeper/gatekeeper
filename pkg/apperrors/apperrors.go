package apperrors

import (
	"errors"
)

var (
	ErrAssertionFailed                 = errors.New("assertion failed")
	ErrPermissionNotInToken            = errors.New("permissions missing in token")
	ErrResourceRetrieve                = errors.New("problem getting resources from IDP")
	ErrTokenScopeNotMatchResourceScope = errors.New("scopes in token doesn't match scopes in IDP resource")
	ErrMissingScopesForResource        = errors.New("missing scopes for resource in IDP provider")
	ErrNoIDPResourceForPath            = errors.New("could not find resource matching path")
	ErrTooManyResources                = errors.New("too many resources got from IDP " +
		"(hint: probably you have multiple resources in IDP with same path and scopes combination)")
	ErrResourceIDNotPresent          = errors.New("resource id not present in token permissions")
	ErrPermissionTicketForResourceID = errors.New("problem getting permission ticket for resourceId")
	ErrRetrieveRPT                   = errors.New("problem getting RPT for resource " +
		"(hint: do you have permissions assigned to resource?)")
	ErrAccessMismatchUmaToken         = errors.New("access token and uma token user ID don't match")
	ErrNoAuthzFound                   = errors.New("no authz found")
	ErrGetIdentityFromUMA             = errors.New("problem getting identity from uma token")
	ErrFailedAuthzRequest             = errors.New("unexpected error occurred during authz request")
	ErrSessionNotFound                = errors.New("authentication session not found in request")
	ErrNoSessionStateFound            = errors.New("no session state found")
	ErrZeroLengthToken                = errors.New("token has zero length")
	ErrInvalidSession                 = errors.New("invalid session identifier")
	ErrRefreshTokenExpired            = errors.New("refresh token has expired")
	ErrUMATokenExpired                = errors.New("uma token expired")
	ErrTokenVerificationFailure       = errors.New("token verification failed")
	ErrDecryption                     = errors.New("failed to decrypt token")
	ErrDefaultDenyWhitelistConflict   = errors.New("you've asked for a default denial but whitelisted everything")
	ErrDefaultDenyUserDefinedConflict = errors.New("you've enabled default deny " +
		"and at the same time defined own rules for /*")
	ErrBadDiscoveryURIFormat     = errors.New("bad discovery url format")
	ErrForwardAuthMissingHeaders = errors.New("seems you are using gatekeeper as forward-auth, " +
		"but you don't forward X-FORWARDED-* headers from front proxy")
	ErrPKCEWithCodeOnly         = errors.New("pkce can be enabled only with no-redirect=false")
	ErrPKCECodeCreation         = errors.New("creation of code verifier failed")
	ErrPKCECookieEmpty          = errors.New("seems that pkce code verifier cookie value is empty string")
	ErrQueryParamValueMismatch  = errors.New("query param value is not allowed")
	ErrMissingAuthCode          = errors.New("missing auth code")
	ErrInvalidGrantType         = errors.New("invalid grant type is not supported")
	ErrSessionExpiredVerifyOff  = errors.New("the session has expired and verification switch off")
	ErrSessionExpiredRefreshOff = errors.New("session expired and access token refreshing is disabled")
	ErrRefreshTokenNotFound     = errors.New("unable to find refresh token for user")
	ErrAccTokenRefreshFailure   = errors.New("failed to refresh the access token")
	ErrEncryptAccToken          = errors.New("unable to encrypt access token")
	ErrEncryptRefreshToken      = errors.New("failed to encrypt refresh token")
	ErrEncryptIDToken           = errors.New("unable to encrypt idToken token")

	ErrDelTokFromStore = errors.New("failed to remove old token")
	ErrSaveTokToStore  = errors.New("failed to store refresh token")

	ErrLoginWithLoginHandleDisabled   = errors.New("attempt to login when login handler is disabled")
	ErrMissingLoginCreds              = errors.New("request does not have both username and password")
	ErrInvalidUserCreds               = errors.New("invalid user credentials")
	ErrAcquireTokenViaPassCredsGrant  = errors.New("unable to request the access token via grant_type 'password'")
	ErrExtractIdentityFromAccessToken = errors.New("unable to extract identity from access token")
	ErrResponseMissingIDToken         = errors.New("token response does not contain an id_token")
	ErrResponseMissingExpires         = errors.New("token response does not contain expires_in")
	ErrParseRefreshToken              = errors.New("failed to parse refresh token")
	ErrParseIDToken                   = errors.New("failed to parse id token")
	ErrParseAccessToken               = errors.New("failed to parse access token")
	ErrParseIDTokenClaims             = errors.New("failed to parse id token claims")
	ErrParseAccessTokenClaims         = errors.New("failed to parse access token claims")
	ErrParseRefreshTokenClaims        = errors.New("failed to parse refresh token claims")
	ErrPATTokenFetch                  = errors.New("failed to get PAT token")

	ErrAccTokenVerifyFailure   = errors.New("access token failed verification")
	ErrTokenSignature          = errors.New("invalid token signature")
	ErrVerifyIDToken           = errors.New("unable to verify ID token")
	ErrVerifyRefreshToken      = errors.New("refresh token failed verification")
	ErrAccRefreshTokenMismatch = errors.New("seems that access token and refresh token doesn't match")

	ErrCreateRevocationReq   = errors.New("unable to construct the revocation request")
	ErrRevocationReqFailure  = errors.New("request to revocation endpoint failed")
	ErrInvalidRevocationResp = errors.New("invalid response from revocation endpoint")

	ErrMarshallDiscoveryResp  = errors.New("problem marshalling discovery response")
	ErrDiscoveryResponseWrite = errors.New("problem during discovery response write")

	ErrHmacHeaderEmpty = errors.New("request HMAC header empty")
	ErrHmacMismatch    = errors.New("received HMAC header and calculated HMAC does not match")

	ErrStartMainHTTP     = errors.New("failed to start main http service")
	ErrStartRedirectHTTP = errors.New("failed to start http redirect service")
	ErrStartAdminHTTP    = errors.New("failed to start admin service")

	// config errors.

	ErrNoRedirectsWithEnableRefreshTokensInvalid = errors.New("no-redirects true cannot be enabled with refresh tokens")
	ErrInvalidPostLoginRedirectPath              = errors.New("post login redirect path invalid, " +
		"should be only path not absolute url (no hostname, scheme)")
	ErrPostLoginRedirectPathNoRedirectsInvalid = errors.New("post login redirect path can be enabled " +
		"only with no-redirect=false")
	ErrMissingListenInterface     = errors.New("you have not specified the listening interface")
	ErrAdminListenerScheme        = errors.New("scheme for admin listener must be one of [http, https]")
	ErrInvalidIdpProviderProxyURI = errors.New("invalid proxy address for IDP provider proxy")
	ErrIDPCAandSkipTLS            = errors.New("you have supplied IDP CA and at the same time skip openid tls verify")
	ErrInvalidMaxIdleConnections  = errors.New("max-idle-connections must be a number > 0")
	ErrInvalidMaxIdleConnsPerHost = errors.New(
		"maxi-idle-connections-per-host must be a " +
			"number > 0 and <= max-idle-connections",
	)
	ErrInvalidSameSiteCookie          = errors.New("same-site-cookie must be one of Strict|Lax|None")
	ErrMissingPrivateKey              = errors.New("you have not provided a private key")
	ErrMissingCert                    = errors.New("you have not provided a certificate file")
	ErrMissingAdminEndpointPrivateKey = errors.New("you have not provided a private key for admin endpoint")
	ErrMissingAdminEndpointCert       = errors.New("you have not provided a certificate file for admin endpoint")
	ErrMissingLetsEncryptCacheDir     = errors.New("the letsencrypt cache dir has not been set")
	ErrMinimalTLSVersionEmpty         = errors.New("minimal TLS version should not be empty")
	ErrInvalidMinimalTLSVersion       = errors.New("invalid minimal TLS version specified")
	ErrInvalidForwardTLSCertOpt       = errors.New("you don't need to specify a tls-certificate, " +
		"use tls-ca-certificate instead")
	ErrInvalidForwardTLSKeyOpt = errors.New("you don't need to specify the tls-private-key, " +
		"use tls-ca-key instead")
	ErrRedundantRedirectURIinForwardAuthMode = errors.New(
		"when in forward-auth mode = " +
			"noproxy=true with noredirect=false, redirectionURL " +
			"should not be set, will be composed from X-FORWARDED-* headers",
	)
	ErrMissingUpstream                   = errors.New("you have not specified an upstream endpoint to proxy to")
	ErrMissingClientID                   = errors.New("you have not specified the client id")
	ErrMissingDiscoveryURI               = errors.New("you have not specified the discovery url")
	ErrMissingForwardUser                = errors.New("no forwarding username")
	ErrMissingForwardPass                = errors.New("no forwarding password")
	ErrMissingClientSecret               = errors.New("you have not specified the client secret")
	ErrSecFilterDisabledForHTTPSRedirect = errors.New(
		"the security filter must be switch on for this feature: http-redirect",
	)
	ErrSecFilterDisabledForXSSFilter = errors.New(
		"the security filter must be switch on for this feature: browser-xss-filter",
	)
	ErrSecFilterDisabledForFrameDenyFilter = errors.New(
		"the security filter must be switch on " +
			"for this feature: frame-deny-filter",
	)
	ErrSecFilterDisabledForCSPFilter = errors.New(
		"the security filter must be switch on " +
			"for this feature: content-security-policy",
	)
	ErrSecFilterDisabledForHostnames = errors.New(
		"the security filter must be switch on for this feature: hostnames",
	)
	ErrMissingEncryptionKey = errors.New(
		"you have not specified an encryption key for encoding the access token",
	)
	ErrMissingEncryptionKeyForRefreshTokens = errors.New(
		"enable refresh tokens requires encryption key to be defined",
	)
	ErrSecureCookieWithNonTLSRedirectionURI = errors.New(
		"the cookie is set to secure but your redirection url is non-tls",
	)
	ErrTooManyExtAuthzEnabled = errors.New(
		"only one type of external authz can be enabled at once",
	)
	ErrMissingClientCredsWithUMA        = errors.New("enable uma requires client credentials")
	ErrEnableUmaIdpSessionCheckConflict = errors.New("you cannot have enable uma together with enable " +
		"idp session check and noredirects")
	ErrTooManyDefaultDenyOpts = errors.New(
		"only one of enable-default-deny/enable-default-deny-strict can be true",
	)
	ErrHmacRequiresEncKey                   = errors.New("enable-hmac requires encryption key")
	ErrPostLogoutRedirectURIRequiresIDToken = errors.New("post logout redirect uri requires id token, " +
		"enable id token cookie")
	ErrAllowedQueryParamsWithNoRedirects = errors.New("allowed-query-params are not valid with noredirects=true")
	ErrDefaultAllowedQueryParamEmpty     = errors.New("default-allowed-query-params value cannot be empty")
	ErrTooManyDefaultAllowedQueryParams  = errors.New("you have more default query params than allowed query params")
	ErrMissingDefaultQueryParamInAllowed = errors.New("param is present in default query params but missing in allowed")
	ErrDefaultQueryParamNotAllowed       = errors.New("default query param is not in allowed query params")
	ErrLoAWithNoRedirects                = errors.New("level of authentication is not valid with noredirects=true")
	ErrLoaWithUMA                        = errors.New("level of authentication is not valid with enable-uma")

	ErrCertSelfNoHostname    = errors.New("no hostnames specified")
	ErrCertSelfLowExpiration = errors.New("expiration must be greater then 5 minutes")

	ErrLetsEncryptMissingCacheDir = errors.New("letsencrypt cache dir has not been set")
	ErrHijackerMethodMissing      = errors.New("writer does not implement http.Hijacker method")
	ErrInvalidOriginWithCreds     = errors.New("origin cannot be set to * together with AllowedCredentials true")
	ErrInvalidCookiePath          = errors.New("cookie path must begin with /")
	ErrMissingStoreURL            = errors.New("missing store url")
	ErrInvalidStoreURL            = errors.New("store url is invalid for non-HA client")
	ErrInvalidHAStoreURL          = errors.New("store url is invalid for HA client")
)
