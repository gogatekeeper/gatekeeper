# Gatekeeper

Gatekeeper is a proxy which integrates with OpenID Connect (OIDC) Providers, it supports both access tokens in a browser cookie or bearer tokens.

This documentation details how to build and configure Gatekeeper followed by details of how to use each of its features.

For further information, see the included help file which includes a
full list of commands and switches. View the file by entering the
following at the command line (modify the location to match where you
install Gatekeeper Proxy):

``` bash
    $ bin/gatekeeper help
```

You can view all settings also in this table [Settings](settings.md)

## Requirements

  - Go 1.18 or higher
  - Make

## Configuration options

Configuration can come from a YAML/JSON file or by using command line
options. Here is a list of options.

``` yaml
# is the URL for retrieve the OpenID configuration
discovery-url: <DISCOVERY URL>
# the client id for the 'client' application
client-id: <CLIENT_ID>
# the secret associated to the 'client' application
client-secret: <CLIENT_SECRET>
# the interface definition you wish the proxy to listen, all interfaces is specified as ':<port>', unix sockets as unix://<REL_PATH>|</ABS PATH>
listen: :3000
# port on which metrics and health endpoints will be available, if not specified it will be on above specified port
listen-admin: :4000
# whether to enable refresh tokens
enable-refresh-tokens: true
# the location of a certificate you wish the proxy to use for TLS support
tls-cert:
# the location of a private key for TLS
tls-private-key:
# TLS options related to admin listener
tls-admin-cert:
tls-admin-private-key:
tls-admin-ca-certificate:
tls-admin-client-certificate:
# the redirection URL, essentially the site URL, note: /oauth/callback is added at the end
redirection-url: http://127.0.0.1:3000
# the encryption key used to encode the session state
encryption-key: <ENCRYPTION_KEY>
# the upstream endpoint which we should proxy request
upstream-url: http://127.0.0.1:80
# Returns HTTP 401 when no authentication is present, used with forward proxies or API protection with client credentials grant.
no-redirects: false
# additional scopes to add to the default (openid+email+profile)
scopes:
- vpn-user
# a collection of resource i.e. URLs that you wish to protect
resources:
- uri: /admin/test
  # the methods on this URL that should be protected, if missing, we assuming all
  methods:
  - GET
  # a list of roles the user must have in order to access URLs under the above
  # If all you want is authentication ONLY, simply remove the roles array - the user must be authenticated but
  # no roles are required
  roles:
  - openvpn:vpn-user
  - openvpn:prod-vpn
  - test
- uri: /admin/*
  methods:
  - GET
  roles:
  - openvpn:vpn-user
  - openvpn:commons-prod-vpn
```

Options issued at the command line have a higher priority and will
override or merge with options referenced in a config file. Examples of
each style are shown in the following sections.

## Example of usage and configuration with Keycloak

Assuming you have some web service you wish protected by
Keycloak:

  - Create the **client** using the Keycloak GUI or CLI; the
    client protocol is **'openid-connect'**, access-type:
    **confidential**.

  - Add a Valid Redirect URI of
    **<http://127.0.0.1:3000/oauth/callback>**.

  - Grab the client id and client secret.

  - Create the roles under the client or existing clients for
    authorization purposes.

Here is an example configuration file.

``` yaml
client-id: <CLIENT_ID>
client-secret: <CLIENT_SECRET> # require for access_type: confidential
# Note the redirection-url is optional, it will default to the X-Forwarded-Proto / X-Forwarded-Host r the URL scheme and host not found
discovery-url: https://keycloak.example.com/auth/realms/<REALM_NAME>
# Indicates we should deny by default all requests and explicitly specify what is permitted
enable-default-deny: true
encryption-key: AgXa7xRcoClDEU0ZDSH4X0XhL5Qy2Z2j
listen: :3000
redirection-url: http://127.0.0.1:3000
upstream-url: http://127.0.0.1:80
resources:
- uri: /admin*
  methods:
  - GET
  roles:
  - client:test1
  - client:test2
  require-any-role: true
  groups:
  - admins
  - users
- uri: /backend*
  roles:
  - client:test1
- uri: /public/*
# Allow access to the resource above
  white-listed: true
- uri: /favicon
# Allow access to the resource above
  white-listed: true
- uri: /css/*
# Allow access to the resource above
  white-listed: true
- uri: /img/*
# Allow access to the resource above
  white-listed: true
# Adds custom headers
headers:
  myheader1: value_1
  myheader2: value_2
```

Anything defined in a configuration file can also be configured using
command line options, such as in this example.

``` bash
bin/gatekeeper \
    --discovery-url=https://keycloak.example.com/auth/realms/<REALM_NAME> \
    --client-id=<CLIENT_ID> \
    --client-secret=<SECRET> \
    --listen=127.0.0.1:3000 \ # unix sockets format unix://path
    --redirection-url=http://127.0.0.1:3000 \
    --enable-refresh-tokens=true \
    --encryption-key=AgXa7xRcoClDEU0ZDSH4X0XhL5Qy2Z2j \
    --upstream-url=http://127.0.0.1:80 \
    --enable-default-deny=true \
    --resources="uri=/admin*|roles=test1,test2" \
    --resources="uri=/backend*|roles=test1" \
    --resources="uri=/css/*|white-listed=true" \
    --resources="uri=/img/*|white-listed=true" \
    --resources="uri=/public/*|white-listed=true" \
    --headers="myheader1=value1" \
    --headers="myheader2=value2"
```

By default, the roles defined on a resource perform a logical `AND` so
all roles specified must be present in the claims, this behavior can be
altered by the `require-any-role` option, however, so as long as one
role is present the permission is granted.

## Authentication flows

You can use gatekeeper to protect APIs, frontend server applications, frontend client applications.
Frontend server-side applications can be protected by Authorization Code Flow, during which several redirection
steps take place. For protecting APIs you can use Client Credentials Grant to avoid redirections steps
involved in authorization code flow you have to use `--no-redirects=true`. For frontend applications
there is PKCE flow which is currently not implemented in gatekeeper, instead you can use Authorization
Code Flow with encrypted refresh token cookies enabled, in this case however you have to handle redirections
at login/logout and you must make cookies available to js (less secure, altough at least they are encrypted).

## Default Deny

`--enable-default-deny` - option blocks all requests without valid token on all basic HTTP methods,
(DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT, TRACE). **WARNING:** There are no additional requirements on
the token, it isn't checked for some claims or roles, groups etc...

`--enable-default-deny-strict` (recommended) - option blocks all requests (including valid token) unless
specific path with requirements specified in resources

## OpenID Provider Communication

By default the communication with the OpenID provider is direct. If you
wish, you can specify a forwarding proxy server in your configuration
file:

``` yaml
openid-provider-proxy: http://proxy.example.com:8080
```

## HTTP routing

By default, all requests will be proxied on to the upstream, if you wish
to ensure all requests are authenticated you can use this:

``` bash
--resource=uri=/* # note, unless specified the method is assumed to be 'any|ANY'
```

The HTTP routing rules follow the guidelines from
[chi](https://github.com/go-chi/chi#router-design). The ordering of the
resources does not matter, the router will handle that for you.

## Session-only cookies

By default, the access and refresh cookies are session-only and disposed
of on browser close; you can disable this feature using the
`--enable-session-cookies` option.

## Cookie Names

There are two parameters which you can use to set up cookie names for access token and refresh token.

```
--cookie-access-name=myAccessTokenCookie
--cookie-refresh-name=myRefreshTokenCookie
```

## Forward-signing proxy

Forward-signing provides a mechanism for authentication and
authorization between services using tokens issued from the IdP. When
operating in this mode the proxy will automatically acquire an access
token (handling the refreshing or logins on your behalf) and tag
outbound requests with an Authorization header. You can control which
domains are tagged with the `--forwarding-domains` option. Note, this
option uses a **contains** comparison on domains. So, if you wanted to
match all domains under \*.svc.cluster.local you can use:
`--forwarding-domain=svc.cluster.local`.

You can choose between two types of OAuth authentications: *password* grant type (default) or *client\_credentials* grant type.

Example setup password grant:

You have a collection of micro-services which are permitted to speak to
one another; you have already set up the credentials, roles, and clients
in Keycloak, providing granular role controls over issue tokens.

``` yaml
- name: gatekeeper
  image: quay.io/gogatekeeper/gatekeeper:1.7.0
  args:
  - --enable-forwarding=true
  - --forwarding-username=projecta
  - --forwarding-password=some_password
  - --forwarding-domains=projecta.svc.cluster.local
  - --forwarding-domains=projectb.svc.cluster.local
  - --client-id=xxxxxx
  - --client-secret=xxxx
  - --discovery-url=http://keycloak:8080/auth/realms/master
  - --tls-ca-certificate=/etc/secrets/ca.pem
  - --tls-ca-key=/etc/secrets/ca-key.pem
  # Note: if you don't specify any forwarding domains, all domains will be signed; Also the code checks is the
  # domain 'contains' the value (it's not a regex) so if you wanted to sign all requests to svc.cluster.local, just use
  # svc.cluster.local
  volumeMounts:
  - name: keycloak-socket
    mountPoint: /var/run/keycloak
- name: projecta
  image: some_images

```

Example setup client credentials grant:

``` yaml
- name: gatekeeper
  image: quay.io/gogatekeeper/gatekeeper:1.7.0
  args:
  - --enable-forwarding=true
  - --forwarding-domains=projecta.svc.cluster.local
  - --forwarding-domains=projectb.svc.cluster.local
  - --client-id=xxxxxx
  - --client-secret=xxxx
  - --discovery-url=http://keycloak:8080/auth/realms/master
  - --tls-ca-certificate=/etc/secrets/ca.pem
  - --tls-ca-key=/etc/secrets/ca-key.pem
  - --forwarding-grant-type=client_credentials
  # Note: if you don't specify any forwarding domains, all domains will be signed; Also the code checks is the
  # domain 'contains' the value (it's not a regex) so if you wanted to sign all requests to svc.cluster.local, just use
  # svc.cluster.local
  volumeMounts:
  - name: keycloak-socket
    mountPoint: /var/run/keycloak
- name: projecta
  image: some_images

```    
Test the forward proxy:

```
curl -k --proxy http://127.0.0.1:3000 https://test.projesta.svc.cluster.local
```

On the receiver side, you could set up the Gatekeeper Proxy
`--no-redirects=true` and permit this to verify and handle admission for
you. Alternatively, the access token can found as a bearer token in the
request.

## Forwarding signed HTTPS connections

Handling HTTPS requires a man-in-the-middle sort of TLS connection. By
default, if no `--tls-ca-certificate` and `--tls-ca-key` are provided
the proxy will use the default certificate. If you wish to verify the
trust, you’ll need to generate a CA, for example.

``` bash
$ openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ca.key -out ca.pem
$ bin/gatekeeper \
  --enable-forwarding \
  --forwarding-username=USERNAME \
  --forwarding-password=PASSWORD \
  --client-id=CLIENT_ID \
  --client-secret=SECRET \
  --discovery-url=https://keycloak.example.com/auth/realms/test \
  --tls-ca-certificate=ca.pem \
  --tls-ca-key=ca-key.pem
```

## Forwarding with UMA token

When `--enable-uma` is set in forwarding mode, proxy signs request with RPT token

## HTTPS redirect

The proxy supports an HTTP listener, so the only real requirement here
is to perform an HTTP → HTTPS redirect. You can enable the option like
this:

``` bash
--listen-http=127.0.0.1:80
--enable-security-filter=true  # is required for the https redirect
--enable-https-redirection
```

## Let’s Encrypt configuration

Here is an example of the required configuration for Let’s Encrypt
support:

``` yaml
listen: 0.0.0.0:443
enable-https-redirection: true
enable-security-filter: true
use-letsencrypt: true
letsencrypt-cache-dir: ./cache/
redirection-url: https://domain.tld:443/
hostnames:
  - domain.tld
```

Listening on port 443 is mandatory.

## Access token encryption

By default, the session token is placed into a cookie in plaintext. If
you prefer to encrypt the session cookie, use the
`--enable-encrypted-token` and `--encryption-key` options. Note that the
access token forwarded in the X-Auth-Token header to upstream is
unaffected.

## Bearer token passthrough

If your Bearer token is intended for your upstream application and not for gatekeeper
you can use option ``--skip-authorization-header-identity``. Please be aware that
token is still required to be in cookies.

## Upstream headers

On protected resources, the upstream endpoint will receive a number of
headers added by the proxy, along with custom claims, like this:

- X-Auth-Email
- X-Auth-ExpiresIn
- X-Auth-Groups
- X-Auth-Roles
- X-Auth-Subject
- X-Auth-Token
- X-Auth-Userid
- X-Auth-Username

To control the `Authorization` header use the
`enable-authorization-header` YAML configuration or the
`--enable-authorization-header` command line option. By default, this
option is set to `true`.

## Custom claim headers

You can inject additional claims from the access token into the
upstream headers with the `--add-claims` option. For example, a
token from a Keycloak provider might include the following
claims:

``` yaml
"resource_access": {},
"name": "Beloved User",
"preferred_username": "beloved.user",
"given_name": "Beloved",
"family_name": "User",
"email": "beloved@example.com"
```

In order to request you receive the *given\_name*, *family\_name*, and name
in the authentication header, we would add `--add-claims=given_name` and
`--add-claims=family_name` and so on, or we can do it in the
configuration file, like this:

``` yaml
add-claims:
- given_name
- family_name
- name
```

This would add the additional headers to the authenticated request along
with standard ones.

``` bash
X-Auth-Family-Name: User
X-Auth-Given-Name: Beloved
X-Auth-Name: Beloved User
```

## Custom headers

You can inject custom headers using the `--headers="name=value"` option
or the configuration file:

    headers:
      name: value

## Encryption key

In order to remain stateless and not have to rely on a central cache to
persist the *refresh\_tokens*, the refresh token is encrypted and added as
a cookie using **crypto/aes**. The key must be the same if you are
running behind a load balancer. The key length should be either *16* or *32*
bytes, depending or whether you want *AES-128* or *AES-256*.

## Claim matching

The proxy supports adding a variable list of claim matches against the
presented tokens for additional access control. You can match the 'iss'
or 'aud' to the token or custom attributes; each of the matches are
regexes. For example, `--match-claims 'aud=sso.*'` or `--claim
iss=https://.*'` or via the configuration file, like this:

``` yaml
match-claims:
  aud: openvpn
  iss: https://keycloak.example.com/auth/realms/commons
```

or via the CLI, like this:

``` bash
--match-claims=auth=openvpn
--match-claims=iss=http://keycloak.example.com/realms/commons
```

You can limit the email domain permitted; for example, if you want to
limit to only users on the example.com domain:

``` yaml
match-claims:
  email: ^.*@example.com$
```

The adapter supports matching on multi-value strings claims. The match
will succeed if one of the values matches, for example:

``` yaml
match-claims:
  perms: perm1
```

will successfully match

``` json
{
  "iss": "https://sso.example.com",
  "sub": "",
  "perms": ["perm1", "perm2"]
}
```

## Group claims

You can match on the group claims within a token via the `groups`
parameter available within the resource. While roles are implicitly
required, such as `roles=admin,user` where the user MUST have roles
'admin' AND 'user', groups are applied with an OR operation, so
`groups=users,testers` requires that the user MUST be within either
'users' OR 'testers'. The claim name is hard-coded to `groups`, so a *JWT*
token would look like this:

``` json
{
  "iss": "https://sso.example.com",
  "sub": "",
  "aud": "test",
  "exp": 1515269245,
  "iat": 1515182845,
  "email": "beloved@example.com",
  "groups": [
    "group_one",
    "group_two"
  ],
  "name": "Beloved"
}
```

## Headers matching

You can match on the request headers  via the `headers`
parameter available within the resource. Headers are implicitly
required, such as `headers=x-some-header:somevalue,x-other-header:othervalue` where the request 
MUST have headers 'x-some-header' with value 'somevalue' AND 'x-other-header', with value 'othervalue'.

## Forward-auth

Traefik, nginx ingress and other gateways usually have feature called forward-auth.
This enables them to forward request to external auth/authz service which returns 2xx in case
auth/authz was successful and otherwise some higher code (usually 401/403). You can use
gatekeeper as this external auth/authz service by using headers matching feature as describe above
and enabling `--no-proxy` option (this option will not forward request to upstream).

Example:

traefik forward-auth configuration

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  labels:
    app.kubernetes.io/name: dashboard-apis-oauth
    app.kubernetes.io/part-of: dashboard
  name: dashboard-apis-oauth
  namespace: censored
spec:
  forwardAuth:
    address: http://gatekeeper-dns-name:4180
```

gatekeeper configuration

```yaml
  - args:
      - --client-id=dashboard
      - --no-redirects=true # this option will ensure there will be no redirects
      - --no-proxy=true # this option will ensure that request will be not forwarded to upstream
      - --listen=0.0.0.0:4180
      - --discovery-url=https://keycloak-dns-name/auth/realms/censored
      - --enable-default-deny=true # this option will ensure protection of all paths /*, according our traefik config, traefik will send it to /
      - --match-headers=headers=x-some-header:somevalue,x-other-header:othervalue
```

## Custom pages

By default, Gatekeeper Proxy will immediately redirect you
for authentication and hand back a 403 for access denied. Most users
will probably want to present the user with a more friendly sign-in and
access denied page. You can pass the command line options (or via config
file) paths to the files with `--sign-in-page=PATH`. The sign-in page
will have a 'redirect' variable passed into the scope and holding the
OAuth redirection URL. If you wish to pass additional variables into the
templates, such as title, sitename and so on, you can use the -`-tags
key=pair` option, like this: `--tags title="This is my site"` and the
variable would be accessible from `{{ .title }}`.

``` html
<html>
<body>
<a href="{{ .redirect }}">Sign-in</a>
</body>
</html>
```

### Custom Error Page for Bad Request

One use case for this is that: inside keycloak server have "required user actions" set to "Terms and Conditions". That means, if it is the first time an user access app X, he will need to accept the T&C or decline. If he accepts the terms, he can login fine to app X. However, if he declines it, he gets an empty error page with "bad request".

You can use built-in template or your custom:

```
--error-page=templates/error.html.tmpl
```

## White-listed URL’s

Depending on how the application URL’s are laid out, you might want
protect the root / URL but have exceptions on a list of paths, for
example `/health`. While this is best solved by adjusting the paths, you
can add exceptions to the protected resources, like this:

``` yaml
  resources:
  - uri: /some_white_listed_url
    white-listed: true
  - uri: /*
    methods:
      - GET
    roles:
      - <CLIENT_APP_NAME>:<ROLE_NAME>
      - <CLIENT_APP_NAME>:<ROLE_NAME>
```

Or on the command line

``` bash
  --resources "uri=/some_white_listed_url|white-listed=true"
  --resources "uri=/*"  # requires authentication on the rest
  --resources "uri=/admin*|roles=admin,superuser|methods=POST,DELETE"
```

## Mutual TLS

The proxy support enforcing mutual TLS for the clients by adding the
`--tls-ca-certificate` command line option or configuration file option.
All clients connecting must present a certificate that was signed by
the CA being used.

## Certificate rotation

The proxy will automatically rotate the server certificates if the files
change on disk. Note, no downtime will occur as the change is made
inline. Clients who connected before the certificate rotation will be
unaffected and will continue as normal with all new connections
presented with the new certificate.

## Refresh tokens

If a request for an access token contains a refresh token and
`--enable-refresh-tokens` is set to `true`, the proxy will automatically
refresh the access token for you. The tokens themselves are kept either
as an encrypted (`--encryption-key=KEY`) cookie **(cookie name:
kc-state).** or a store **(still requires encryption key)**.

At present the only store options supported are
[Redis](https://github.com/antirez/redis) and

To enable a local Redis store use `redis://[USER:PASSWORD@]HOST:PORT`.
In both cases, the refresh token is encrypted before being placed into
the store.

## Logout endpoint

A **/oauth/logout?redirect=url** is provided as a helper to log users
out. In addition to dropping any session cookies, we also attempt to
revoke access via revocation URL (config **revocation-url** or
**--revocation-url**) with the provider. For Keycloak, the URL for this
would be
<https://keycloak.example.com/auth/realms/REALM_NAME/protocol/openid-connect/logout>.
If the URL is not specified we will attempt to grab the URL from the
OpenID discovery response.

## Cross-origin resource sharing (CORS)

You can add a CORS header via the `--cors-[method]` with these
configuration options.

  - Access-Control-Allow-Origin

  - Access-Control-Allow-Methods

  - Access-Control-Allow-Headers

  - Access-Control-Expose-Headers

  - Access-Control-Allow-Credentials

  - Access-Control-Max-Age

You can add using the config file:

``` yaml
cors-origins:
- '*'
cors-methods:
- GET
- POST
```

or via the command line:

``` bash
--cors-origins [--cors-origins option]                  a set of origins to add to the CORS access control (Access-Control-Allow-Origin)
--cors-methods [--cors-methods option]                  the method permitted in the access control (Access-Control-Allow-Methods)
--cors-headers [--cors-headers option]                  a set of headers to add to the CORS access control (Access-Control-Allow-Headers)
--cors-exposes-headers [--cors-exposes-headers option]  set the expose cors headers access control (Access-Control-Expose-Headers)
```

## Upstream URL

You can control the upstream endpoint via the `--upstream-url` option.
Both HTTP and HTTPS are supported with TLS verification and keep-alive
support configured via the `--skip-upstream-tls-verify` /
`--upstream-keepalives` option. Note, the proxy can also upstream via a
UNIX socket, `--upstream-url unix://path/to/the/file.sock`.

## Endpoints

  - **/oauth/authorize** is authentication endpoint which will generate
    the OpenID redirect to the provider

  - **/oauth/callback** is provider OpenID callback endpoint

  - **/oauth/expired** is a helper endpoint to check if a access token
    has expired, 200 for ok and, 401 for no token and 401 for expired

  - **/oauth/health** is the health checking endpoint for the proxy, you
    can also grab version from headers

  - **/oauth/login** provides a relay endpoint to login via
    `grant_type=password`, for example, `POST /oauth/login` form values
    are `username=USERNAME&password=PASSWORD` (must be enabled)

  - **/oauth/logout** provides a convenient endpoint to log the user
    out, it will always attempt to perform a back channel log out of
    offline tokens

  - **/oauth/token** is a helper endpoint which will display the current
    access token for you

  - **/oauth/metrics** is a Prometheus metrics handler

  - **/oauth/discovery** provides endpoint with basic urls gatekeeper provides

## External Authorization

In version 1.5.0 we are introducing external authorization `--enable-uma`, only applicable with `--no-redirects` option for now.
You have to also either populate resources or use `--enable-default-deny` (see examples in previous sections). So you can mix both external authorization+static resource permissions, but
we don't recommend it to not overcomplicate setup. First is always external authorization then static resource authorization.
As it is new feature please don't use it in production, we would like first to receive feedback/testing by community. 
Right now we use external authorization options provided by Keycloak which are specified in UMA (user managed access specification [UMA](https://www.riskinsight-wavestone.com/en/2018/09/demystifying-uma2/)).
To use this feature you need to execute these actions in keycloak:

1. enable authorization for client in keycloak
2. in client authorization tab, you should have protected resource
3. protected resource should have User-Managed Access enabled
4. protected resource should have at least one authorization scope
5. protected resource should have proper permissions set

[Example Keycloak Authorization Guide](https://gruchalski.com/posts/2020-09-05-introduction-to-keycloak-authorization-services/).

To access endpoint protected by gatekeeper with authorization enabled you have to get RPT token.
You can do that by performing following steps:

1. Request token as you would do normally (e.g. in our case using password grant), we will store it in TOKEN variable:

    ```
    curl -X POST -d "username=test&password=test&client_id=test&client_secret=test&gran_type=password" http://examplekeycloak.com/auth/example/admin/protocol/openid-connect/token
    ```

2. accessing endpoint protected by gatekeeper which will return 401 with this response and UMA ticket, we will store it in TICKET variable:

    accessing protected endpoint

    ```
    curl http://example.com/protectedendpoint
    ```

    will return

    ```
    WWW-Authenticate: realm="example", as_uri="http://examplekeycloak.com", ticket="eseiose.slidsds....."
    ```

3. Value in WWW-Authenticate header is UMA ticket. We will use this ticket (in case of keycloak it is also jwt token),
along with our token to get RPT token, we will store it in RPT variable.

    ```
    curl -X POST -d "ticket=$TICKET" -H "Authorization: Bearer $TOKEN" http://examplekeycloak.com/auth/example/admin/protocol/openid-connect/token
    ```

    This will return RPT token which we can use to access endpoint protected by gatekeeper authorization.

4. access protected endpoint

    ```
    curl -H "Authorization: Bearer $RPT" http://example.com/protectedendpoint
    ```

## Request tracing

Usually when there are multiple http services involved in serving user requests
you need to use X-REQUEST-ID or some other header to track request flow through
services. To make this possible with gatekeeper you can enable header logging
by enabling `--enable-logs` and `--verbose` options. Also you can use `request-id-header`
and `enable-request-id` options, which will generate unique uuid and will inject in
header supplied in `request-id-header` option.

## Metrics

Assuming `--enable-metrics` has been set, a Prometheus endpoint can be
found on **/oauth/metrics**; at present the only metric being exposed is
a counter per HTTP code.

## Limitations

Keep in mind [browser cookie
limits](http://browsercookielimits.squawky.net/) if you use access or
refresh tokens in the browser cookie. Gatekeeper Proxy divides
the cookie automatically if your cookie is longer than 4093 bytes. The real
size of the cookie depends on the content of the issued access token.
Also, encryption might add additional bytes to the cookie size. If you
have large cookies (\>200 KB), you might reach browser cookie limits.

All cookies are part of the header request, so you might find a problem
with the max headers size limits in your infrastructure (some load
balancers have very low this value, such as 8 KB). Be sure that all
network devices have sufficient header size limits. Otherwise, your
users won’t be able to obtain an access token.

## Known Issues

There is a known issue with the Keycloak server 4.6.0.Final in which
Gatekeeper Proxy is unable to find the *client\_id* in the *aud* claim. This
is due to the fact the *client\_id* is not in the audience anymore. The
workaround is to add the "Audience" protocol mapper to the client with
the audience pointed to the *client\_id*. For more information, see
[KEYCLOAK-8954](https://issues.redhat.com/browse/KEYCLOAK-8954).

you can now use `--skip-access-token-clientid-check` and
`--skip-access-token-issuer-check` to overcome this limitations.
