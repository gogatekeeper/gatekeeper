---
title: "Configuration Reference"
weight: 2
---

| CONFIG                                     | DESCRIPTION | DEFAULT | ENV |
--- | --- | --- | ---
|    --config value                          | path the a configuration file | | PROXY_CONFIG_FILE
|    --listen value                          | Defines the binding interface for main listener, e.g. {address}:{port}. This is required and there is no default value | | PROXY_LISTEN
|    --listen-http value                     | interface we should be listening to for HTTP traffic | | PROXY_LISTEN_HTTP
|    --listen-admin value                    | defines the interface to bind admin-only endpoint (live-status, debug, prometheus...). If not defined, this defaults to the main listener defined by Listen | | PROXY_LISTEN_ADMIN
|    --listen-admin-scheme value             | scheme to serve admin-only endpoint (http or https). | | PROXY_LISTEN_ADMIN_SCHEME
|    --discovery-url value                   | discovery url to retrieve the openid configuration | | PROXY_DISCOVERY_URL
|    --client-id value                       | client id used to authenticate to the oauth service | | PROXY_CLIENT_ID
|    --client-secret value                   | client secret used to authenticate to the oauth service | | PROXY_CLIENT_SECRET
|    --redirection-url value                 | redirection url for the oauth callback url, defaults to host header if absent | | PROXY_REDIRECTION_URL
|    --post-logout-redirect-uri value        | url to which client is redirected after successful logout | | PROXY_POST_LOGOUT_REDIRECT_URI
|    --revocation-url value                  | url for the revocation endpoint to revoke refresh token | | PROXY_REVOCATION_URL
|    --skip-openid-provider-tls-verify       | skip the verification of any TLS communication with the openid provider | false | PROXY_SKIP_OPENID_PROVIDER_TLSVERIFY
|    --openid-provider-proxy value           | proxy for communication with the openid provider | | PROXY_OPENID_PROVIDER_PROXY
|    --openid-provider-timeout value         | timeout for openid configuration on .well-known/openid-configuration | 30s | PROXY_OPENID_PROVIDER_TIMEOUT
|    --base-uri value                        | common prefix for all URIs | | PROXY_BASE_URI
|    --oauth-uri value                       | the uri for proxy oauth endpoints | /oauth | PROXY_OAUTH_URI
|    --scopes value                          | list of scopes requested when authenticating the user | |
|    --upstream-url value                    | url for the upstream endpoint you wish to proxy | | PROXY_UPSTREAM_URL
|    --upstream-ca value                     | the path to a file container a CA certificate to validate the upstream tls endpoint | | PROXY_UPSTREAM_CA
|    --resources value                       | list of resources 'uri=/admin*\|methods=GET,PUT\|roles=role1,role2' | |
|    --headers value                         | custom headers to the upstream request, key=value | |
|    --preserve-host                         | preserve the host header of the proxied request in the upstream request | false | PROXY_PRESERVE_HOST
|    --request-id-header value               | the http header name for request id | X-Request-ID | PROXY_REQUEST_ID_HEADER
|    --response-headers value                | custom headers to added to the http response key=value | | PROXY_RESPONSE_HEADERS
|    --custom-http-methods                   | list of additional non-standard http methods | |
|    --enable-self-signed-tls                | create self signed certificates for the proxy | false | PROXY_ENABLE_SELF_SIGNED_TLS
|    --self-signed-tls-hostnames value       | a list of hostnames to place on the self-signed certificate | |
|    --self-signed-tls-expiration value      | the expiration of the certificate before rotation | 3h0m0s | PROXY_SELF_SIGNED_TLS_EXPIRATION
|    --enable-request-id                     | indicates we should add a request id if none found | false | PROXY_ENABLE_REQUEST_ID |
|    --enable-logout-redirect                | indicates we should redirect to the identity provider for logging out | false | PROXY_ENABLE_LOGOUT_REDIRECT
|    --enable-default-deny                   | enables a default denial on all requests, requests with valid token are permitted, you have to explicitly say what is permitted | true | PROXY_ENABLE_DEFAULT_DENY
|    --enable-default-deny-strict            | enables a default denial on all requests, requests with valid token are denied, you have to explicitly say what is permitted (recommended) | false | PROXY_ENABLE_DEFAULT_DENY_STRICT
|    --enable-encrypted-token                | enable encryption for the access tokens | false | PROXY_ENABLE_ENCRYPTED_TOKEN
|    --force-encrypted-cookie                | force encryption for the access tokens in cookies | false | PROXY_FORCE_ENCRYPTED_COOKIE
|    --enable-logging                        | enable http logging of the requests | false | PROXY_ENABLE_LOGGING
|    --enable-json-logging                   | switch on json logging rather than text | false | PROXY_ENABLE_JSON_LOGGING
|    --enable-forwarding                     | enables the forwarding proxy mode, signing outbound request | false | PROXY_ENABLE_FORWARDING
|    --enable-security-filter                | enables the security filter handler | false | PROXY_ENABLE_SECURITY_FILTER
|    --enable-refresh-tokens                 | enables the handling of the refresh tokens | false | PROXY_ENABLE_REFRESH_TOKEN
|    --enable-session-cookies                | access and refresh tokens are session only i.e. removed browser close | true | PROXY_ENABLE_SESSION_COOKIES
|    --enable-login-handler                  | enables the handling of the refresh tokens | false | PROXY_ENABLE_LOGIN_HANDLER
|    --enable-token-header                   | enables the token authentication header X-Auth-Token to upstream | true | PROXY_ENABLE_TOKEN_HEADER
|    --enable-authorization-header           | adds the authorization header to the proxy request | true | PROXY_ENABLE_AUTHORIZATION_HEADER
|    --enable-authorization-cookies          | adds the authorization cookies to the uptream proxy request | true | PROXY_ENABLE_AUTHORIZATION_COOKIES
|    --enable-https-redirection              | enable the http to https redirection on the http service | false | PROXY_ENABLE_HTTPS_REDIRECT
|    --enable-profiling                      | switching on the golang profiling via pprof on /debug/pprof, /debug/pprof/heap etc | false | PROXY_ENABLE_PROFILING
|    --enable-metrics                        | enable the prometheus metrics collector on /oauth/metrics | false | PROXY_ENABLE_METRICS
|    --filter-browser-xss                    | enable the adds the X-XSS-Protection header with mode=block | false | PROXY_ENABLE_BROWSER_XSS_FILTER
|    --filter-content-nosniff                | adds the X-Content-Type-Options header with the value nosniff | false | PROXY_ENABLE_CONTENT_NO_SNIFF
|    --filter-frame-deny                     | enable to the frame deny header | false | PROXY_ENABLE_FRAME_DENY
|    --content-security-policy value         | specify the content security policy | | PROXY_CONTENT_SECURITY_POLICY
|    --localhost-metrics                     | enforces the metrics page can only been requested from 127.0.0.1 | false | PROXY_LOCALHOST_METRICS
|    --enable-compression                    | enable gzip compression for response | false | PROXY_ENABLE_COMPRESSION
|    --enable-pkce                           | enable pkce for auth code flow, only S256 code challenge supported | false | ENABLE_PKCE
|    --enable-uma                            | enable UMA authorization, please don't use in production as it is new feature, we would like to receive feedback first             | false | PROXY_ENABLE_UMA
|	 --enable-opa                            | enable authorization with external Open policy agent  | false | PROXY_ENABLE_OPA
|	 --opa-timeout                           | timeout for connection to OPA                         |   10s | PROXY_OPA_TIMEOUT
|	 --opa-authz-uri                         | OPA endpoint address with path                        |       | PROXY_OPA_AUTHZ_URI
|    --pat-retry-count                       | number of retries to get PAT                          |    5  | PROXY_PAT_RETRY_COUNT
|    --pat-retry-interval                    | interval between retries to get PAT                   |    2s | PROXY_PAT_RETRY_INTERVAL
|    --access-token-duration value           | fallback cookie duration for the access token when using refresh tokens | 720h0m0s | PROXY_ACCESS_TOKEN_DURATION
|    --cookie-domain value                   | domain the access cookie is available to, defaults host header | | PROXY_COOKIE_DOMAIN
|    --cookie-access-name value              | name of the cookie use to hold the access token | kc-access | PROXY_COOKIE_ACCESS_NAME
|    --cookie-refresh-name value             | name of the cookie used to hold the encrypted refresh token | kc-state | PROXY_COOKIE_REFRESH_NAME
|    --cookie-oauth-state-name value         | name of the cookie used to hold the Oauth request state | OAuth_Token_Request_State | COOKIE_OAUTH_STATE_NAME
|    --cookie-request-uri-name value             | name of the cookie used to hold the request uri | request_uri | COOKIE_REQUEST_URI_NAME
|    --cookie-pkce-name value                | name of the cookie used to hold PKCE code verifier | pkce | COOKIE_PKCE_NAME
|    --secure-cookie                         | enforces the cookie to be secure | true | PROXY_SECURE_COOKIE
|    --http-only-cookie                      | enforces the cookie is in http only mode | true | PROXY_HTTP_ONLY_COOKIE
|    --same-site-cookie value                | enforces cookies to be send only to same site requests according to the policy (can be \| Strict\|Lax\|None) | Lax | PROXY_SAME_SITE_COOKIE
|    --match-claims value                    | keypair values for matching access token claims e.g. aud=myapp, iss=http://example.* | |
|    --add-claims value                      | extra claims from the token and inject into headers, e.g given_name -> X-Auth-Given-Name | |
|    --tls-min-version                       | specify server minimal TLS version one of tlsv1.0,tlsv1.1,tlsv1.2,tlsv1.3 | | TLS_MIN_VERSION |
|    --tls-cert value                        | path to ths TLS certificate | | PROXY_TLS_CERTIFICATE
|    --tls-private-key value                 | path to the private key for TLS | | PROXY_TLS_PRIVATE_KEY
|    --tls-ca-certificate value              | path to the ca certificate used for signing requests | | PROXY_TLS_CA_CERTIFICATE
|    --tls-ca-key value                      | path the ca private key, used by the forward signing proxy | | PROXY_TLS_CA_PRIVATE_KEY
|    --tls-client-certificate value          | path to the client certificate for outbound connections in reverse and forwarding proxy modes | | PROXY_TLS_CLIENT_CERTIFICATE
|    --skip-upstream-tls-verify              | skip the verification of any upstream TLS | true | PROXY_SKIP_UPSTREAM_TLS_VERIFY
|    --tls-admin-cert value                  | path to ths TLS certificate | | PROXY_TLS_ADMIN_CERTIFICATE |
|    --tls-admin-private-key value           | path to the private key for TLS | | PROXY_TLS_ADMIN_PRIVATE_KEY |
|    --tls-admin-ca-certificate value        | path to the ca certificate used for signing requests | | PROXY_TLS_ADMIN_CA_CERTIFICATE |
|    --tls-admin-client-certificate value    | path to the client certificate for outbound connections in reverse and forwarding proxy modes | | PROXY_TLS_ADMIN_CLIENT_CERTIFICATE |
|    --cors-origins value                    | origins to add to the CORE origins control (Access-Control-Allow-Origin) | |
|    --cors-methods value                    | methods permitted in the access control (Access-Control-Allow-Methods) | |
|    --cors-headers value                    | set of headers to add to the CORS access control (Access-Control-Allow-Headers) | |
|    --cors-exposed-headers value            | expose cors headers access control (Access-Control-Expose-Headers) | |
|    --cors-credentials                      | credentials access control header (Access-Control-Allow-Credentials) | false | PROXY_CORS_CREDENTIALS
|    --cors-max-age value                    | max age applied to cors headers (Access-Control-Max-Age) | 0s | PROXY_CORS_MAX_AGE
|    --hostnames value                       | list of hostnames the service will respond to | |
|    --store-url value                       | url for the storage subsystem, e.g redis://127.0.0.1:6379, file:///etc/tokens.file | | PROXY_STORE_URL
|    --encryption-key value                  | encryption key used to encryption the session state | | PROXY_ENCRYPTION_KEY
|    --no-proxy value                        | do not proxy requests to upstream, useful for forward-auth usage (with nginx, traefik) | | PROXY_NO_PROXY
|    --no-redirects                          | do not have back redirects when no authentication is present, 401 them | false | PROXY_NO_REDIRECTS
|    --skip-token-verification               | TESTING ONLY; bypass token verification, only expiration and roles enforced | false | PROXY_SKIP_TOKEN_VERIFICATION
|    --skip-access-token-issuer-check        | according RFC issuer should not be checked on access token, this will be default true in future | false | PROXY_SKIP_ACCESS_TOKEN_ISSUER_CHECK
|    --skip-access-token-clientid-check      | according RFC client id should not be checked on access token, this will be default true in future | false | PROXY_SKIP_ACCESS_TOKEN_CLIENT_ID_CHECK
| --skip-authorization-header-identity | skip authorization header identity, means that we won't be extracting token from authorization header, only from cookie or fail if even no cookie present (e.g. if authorization header is used only by application behind gatekeeper)"` | false | PROXY_SKIP_AUTHORIZATION_HEADER_IDENTITY
|    --upstream-keepalives                    | enables or disables the keepalive connections for upstream endpoint | true | PROXY_UPSTREAM_KEEPALIVES
|    --upstream-timeout value                 | maximum amount of time a dial will wait for a connect to complete | 10s | PROXY_UPSTREAM_TIMEOUT
|    --upstream-keepalive-timeout value       | specifies the keep-alive period for an active network connection | 10s | PROXY_UPSTREAM_KEEPALIVE_TIMEOUT
|    --upstream-tls-handshake-timeout value   | the timeout placed on the tls handshake for upstream | 10s | PROXY_UPSTREAM_TLS_HANDSHAKE_TIMEOUT
|    --upstream-response-header-timeout value | the timeout placed on the response header for upstream | 10s | PROXY_UPSTREAM_RESPONSE_HEADER_TIMEOUT
|    --upstream-expect-continue-timeout value | the timeout placed on the expect continue for upstream | 10s | PROXY_UPSTREAM_EXPECT_CONTINUE_TIMEOUT
|    --verbose                                | switch on debug / verbose logging | false | PROXY_VERBOSE
|    --enabled-proxy-protocol                 | enable proxy protocol | false | PROXY_ENABLE_PROXY_PROTOCOL
|    --max-idle-connections value             | max idle upstream / keycloak connections to keep alive, ready for reuse | 0 | PROXY_MAX_IDLE_CONNS
|    --max-idle-connections-per-host value    | limits the number of idle connections maintained per host | 0 | PROXY_MAX_IDLE_CONNS_PER_HOST
|    --server-read-timeout value              | the server read timeout on the http server | 10s | PROXY_SERVER_READ_TIMEOUT
|    --server-write-timeout value             | the server write timeout on the http server | 10s | PROXY_SERVER_WRITE_TIMEOUT
|    --server-idle-timeout value              | the server idle timeout on the http server | 2m0s | PROXY_SERVER_IDLE_TIMEOUT
|    --use-letsencrypt                        | use letsencrypt for certificates | false | PROXY_USE_LETS_ENCRYPT
|    --letsencrypt-cache-dir value            | path where cached letsencrypt certificates are stored | ./cache/ | PROXY_LETS_ENCRYPT_CACHE_DIR
|    --sign-in-page value                     | path to custom template displayed for signin | | PROXY_SIGN_IN_PAGE
|    --forbidden-page value                   | path to custom template used for access forbidden | | PROXY_FORBIDDEN_PAGE
|    --error-page value                       | path to custom template displayed for http.StatusBadRequest | | PROXY_ERROR_PAGE
|    --tags value                             | keypairs passed to the templates at render,e.g title=Page | |
|    --forwarding-grant-type value            | grant-type to use when logging into the openid provider, can be one of password, client_credentials | password | PROXY_FORWARDING_GRANT_TYPE
|    --forwarding-username value              | username to use when logging into the openid provider | | PROXY_FORWARDING_USERNAME
|    --forwarding-password value              | password to use when logging into the openid provider | | PROXY_FORWARDING_PASSWORD
|    --forwarding-domains value               | list of domains which should be signed; everything else is relayed unsigned | |
|    --disable-all-logging                    | disables all logging to stdout and stderr | false | PROXY_DISABLE_ALL_LOGGING
|    --help, -h                               | show help
|    --version, -v                            | print the version
|
