package main

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/jochasinga/relay"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/websocket"
	jose2 "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"io/ioutil"
	"log"
	"net"
	"testing"

	resty "github.com/go-resty/resty/v2"
	uuid "github.com/gofrs/uuid"
	"github.com/oleiade/reflections"
	strcase "github.com/stoewer/go-strcase"
)

const (
	fakeAdminRole          = "role:admin"
	fakeAdminRoleURL       = "/admin*"
	fakeAuthAllURL         = "/auth_all/*"
	fakeClientID           = "test"
	fakeSecret             = "test"
	fakeTestAdminRolesURL  = "/test_admin_roles"
	fakeTestRole           = "role:test"
	fakeTestRoleURL        = "/test_role"
	fakeTestWhitelistedURL = "/auth_all/white_listed*"
	testProxyAccepted      = "Proxy-Accepted"
	validUsername          = "test"
	validPassword          = "test"
)

type RoleClaim struct {
	Roles []string `json:"roles"`
}

type DefaultTestTokenClaims struct {
	Aud               string                    `json:"aud"`
	Azp               string                    `json:"azp"`
	ClientSession     string                    `json:"client_session"`
	Email             string                    `json:"email"`
	FamilyName        string                    `json:"family_name"`
	GivenName         string                    `json:"given_name"`
	Username          string                    `json:"username"`
	Iat               int64                     `json:"iat"`
	Iss               string                    `json:"iss"`
	Jti               string                    `json:"jti"`
	Name              string                    `json:"name"`
	Nbf               int                       `json:"nbf"`
	Exp               int64                     `json:"exp"`
	PreferredUsername string                    `json:"preferred_username"`
	SessionState      string                    `json:"session_state"`
	Sub               string                    `json:"sub"`
	Typ               string                    `json:"typ"`
	Groups            []string                  `json:"groups"`
	RealmAccess       RoleClaim                 `json:"realm_access"`
	ResourceAccess    map[string]RoleClaim      `json:"resource_access"`
	Item              string                    `json:"item"`
	Found             string                    `json:"found"`
	Item1             []string                  `json:"item1"`
	Item2             []string                  `json:"item2"`
	Item3             []string                  `json:"item3"`
	Authorization     authorization.Permissions `json:"authorization"`
}

var defTestTokenClaims = DefaultTestTokenClaims{
	Aud:               "test",
	Azp:               "clientid",
	ClientSession:     "f0105893-369a-46bc-9661-ad8c747b1a69",
	Email:             "gambol99@gmail.com",
	FamilyName:        "Jayawardene",
	GivenName:         "Rohith",
	Username:          "Jayawardene",
	Iat:               1450372669,
	Iss:               "test",
	Jti:               "4ee75b8e-3ee6-4382-92d4-3390b4b4937b",
	Name:              "Rohith Jayawardene",
	Nbf:               0,
	Exp:               0,
	PreferredUsername: "rjayawardene",
	SessionState:      "98f4c3d2-1b8c-4932-b8c4-92ec0ea7e195",
	Sub:               "1e11e539-8256-4b3b-bda8-cc0d56cddb48",
	Typ:               "Bearer",
	Groups:            []string{"default"},
	RealmAccess:       RoleClaim{Roles: []string{"default"}},
	ResourceAccess: map[string]RoleClaim{
		"defaultclient": {
			Roles: []string{"default"},
		},
	},
	Item:  "item",
	Item1: []string{"default"},
	Item2: []string{"default"},
	Item3: []string{"default"},
}

const (
	testEncryptionKey = "ZSeCYDUxIlhDrmPpa1Ldc7il384esSF2"
)

type fakeRequest struct {
	BasicAuth                     bool
	Cookies                       []*http.Cookie
	Expires                       time.Duration
	FormValues                    map[string]string
	Groups                        []string
	HasCookieToken                bool
	HasLogin                      bool
	HasToken                      bool
	Headers                       map[string]string
	Method                        string
	NotSigned                     bool
	OnResponse                    func(int, *resty.Request, *resty.Response)
	Password                      string
	ProxyProtocol                 string
	ProxyRequest                  bool
	RawToken                      string
	Redirects                     bool
	Roles                         []string
	SkipClientIDCheck             bool
	SkipIssuerCheck               bool
	RequestCA                     string
	TokenClaims                   map[string]interface{}
	TokenAuthorization            *authorization.Permissions
	URI                           string
	URL                           string
	Username                      string
	TLSMin                        uint16
	TLSMax                        uint16
	ExpectedCode                  int
	ExpectedContent               func(body string, testNum int)
	ExpectedContentContains       string
	ExpectedRequestError          string
	ExpectedCookies               map[string]string
	ExpectedHeaders               map[string]string
	ExpectedLocation              string
	ExpectedNoProxyHeaders        []string
	ExpectedProxy                 bool
	ExpectedProxyHeaders          map[string]string
	ExpectedProxyHeadersValidator map[string]func(*testing.T, *Config, string)
	ExpectedCookiesValidator      map[string]func(*testing.T, *Config, string) bool
	ExpectedLoginCookiesValidator map[string]func(*testing.T, *Config, string) bool
}

type fakeProxy struct {
	config  *Config
	idp     *fakeAuthServer
	proxy   *oauthProxy
	cookies map[string]*http.Cookie
}

func newFakeProxy(cfg *Config, authConfig *fakeAuthConfig) *fakeProxy {
	log.SetOutput(ioutil.Discard)

	if cfg == nil {
		cfg = newFakeKeycloakConfig()
	}

	auth := newFakeAuthServer(authConfig)

	if authConfig.EnableProxy {
		cfg.OpenIDProviderProxy = auth.getProxyURL()
	}

	cfg.DiscoveryURL = auth.getLocation()
	// c.Verbose = true
	cfg.DisableAllLogging = true
	err := cfg.update()

	if err != nil {
		panic("failed to create fake proxy service, error: " + err.Error())
	}

	proxy, err := newProxy(cfg)

	if err != nil {
		panic("failed to create fake proxy service, error: " + err.Error())
	}

	// proxy.log = zap.NewNop()

	if cfg.Upstream == "" {
		proxy.upstream = &fakeUpstreamService{}
	}

	if err = proxy.Run(); err != nil {
		panic("failed to create the proxy service, error: " + err.Error())
	}

	cfg.RedirectionURL = fmt.Sprintf("http://%s", proxy.listener.Addr().String())

	return &fakeProxy{cfg, auth, proxy, make(map[string]*http.Cookie)}
}

func (f *fakeProxy) getServiceURL() string {
	return fmt.Sprintf("http://%s", f.proxy.listener.Addr().String())
}

// RunTests performs a series of requests against a fake proxy service
//nolint:gocyclo,funlen,cyclop
func (f *fakeProxy) RunTests(t *testing.T, requests []fakeRequest) {
	defer func() {
		f.idp.Close()
		f.proxy.server.Close()
	}()

	for idx := range requests {
		reqCfg := requests[idx]
		var upstream fakeUpstreamResponse

		f.config.NoRedirects = !reqCfg.Redirects
		f.config.SkipAccessTokenClientIDCheck = reqCfg.SkipClientIDCheck
		f.config.SkipAccessTokenIssuerCheck = reqCfg.SkipIssuerCheck
		// we need to set any defaults
		if reqCfg.Method == "" {
			reqCfg.Method = http.MethodGet
		}
		// create a http client
		client := resty.New()

		if reqCfg.TLSMin != 0 {
			client.SetTLSClientConfig(&tls.Config{MinVersion: reqCfg.TLSMin})
		}

		if reqCfg.TLSMax != 0 {
			client.SetTLSClientConfig(&tls.Config{MaxVersion: reqCfg.TLSMax})
		}

		request := client.SetRedirectPolicy(resty.NoRedirectPolicy()).R()

		if reqCfg.ProxyProtocol != "" {
			client.SetTransport(&http.Transport{
				Dial: func(network, addr string) (net.Conn, error) {
					conn, err := net.Dial("tcp", addr)

					if err != nil {
						return nil, err
					}

					header := fmt.Sprintf(
						"PROXY TCP4 %s 10.0.0.1 1000 2000\r\n",
						reqCfg.ProxyProtocol,
					)
					_, _ = conn.Write([]byte(header))

					return conn, nil
				},
			})
		}

		if reqCfg.RequestCA != "" {
			client.SetRootCertificateFromString(reqCfg.RequestCA)
		}

		// are we performing a oauth login beforehand
		if reqCfg.HasLogin {
			if err := f.performUserLogin(reqCfg.URI); err != nil {
				t.Errorf(
					"case %d, unable to login to oauth server, error: %s",
					idx,
					err,
				)
				return
			}
		}

		if len(f.cookies) > 0 {
			for _, k := range f.cookies {
				client.SetCookie(k)
			}
		}

		if reqCfg.ExpectedProxy {
			request.SetResult(&upstream)
		}

		if reqCfg.ProxyRequest {
			client.SetProxy(f.getServiceURL())
		}

		if reqCfg.BasicAuth {
			request.SetBasicAuth(reqCfg.Username, reqCfg.Password)
		}

		if reqCfg.RawToken != "" {
			setRequestAuthentication(f.config, client, request, &reqCfg, reqCfg.RawToken)
		}

		if len(reqCfg.Cookies) > 0 {
			client.SetCookies(reqCfg.Cookies)
		}

		if len(reqCfg.Headers) > 0 {
			request.SetHeaders(reqCfg.Headers)
		}

		if reqCfg.FormValues != nil {
			request.SetFormData(reqCfg.FormValues)
		}

		if reqCfg.HasToken {
			token := newTestToken(f.idp.getLocation())

			if reqCfg.TokenClaims != nil && len(reqCfg.TokenClaims) > 0 {
				for i := range reqCfg.TokenClaims {
					err := reflections.SetField(
						&token.claims,
						strcase.UpperCamelCase(i),
						reqCfg.TokenClaims[i],
					)
					assert.NoError(t, err)
				}
			}

			if len(reqCfg.Roles) > 0 {
				token.addRealmRoles(reqCfg.Roles)
			}

			if len(reqCfg.Groups) > 0 {
				token.addGroups(reqCfg.Groups)
			}

			if reqCfg.Expires > 0 || reqCfg.Expires < 0 {
				token.setExpiration(time.Now().Add(reqCfg.Expires))
			}

			if reqCfg.TokenAuthorization != nil {
				token.claims.Authorization = *reqCfg.TokenAuthorization
			}

			if reqCfg.NotSigned {
				authToken, err := token.getUnsignedToken()
				assert.NoError(t, err)
				setRequestAuthentication(f.config, client, request, &reqCfg, authToken)
			} else {
				authToken, err := token.getToken()
				assert.NoError(t, err)
				setRequestAuthentication(f.config, client, request, &reqCfg, authToken)
			}
		}

		// step: execute the request
		var resp *resty.Response
		var err error

		switch reqCfg.URL {
		case "":
			resp, err = request.Execute(reqCfg.Method, f.getServiceURL()+reqCfg.URI)
		default:
			resp, err = request.Execute(reqCfg.Method, reqCfg.URL)
		}

		if reqCfg.ExpectedRequestError != "" {
			if !strings.Contains(err.Error(), reqCfg.ExpectedRequestError) {
				assert.Fail(
					t,
					"case %d, expected error %s, got error: %s",
					idx,
					reqCfg.ExpectedRequestError,
					err,
				)
			}
		} else if err != nil {
			if !strings.Contains(err.Error(), "auto redirect is disabled") {
				assert.NoError(
					t,
					err,
					"case %d, unable to make request, error: %s",
					idx,
					err,
				)
				continue
			}
		}

		status := resp.StatusCode()

		if reqCfg.ExpectedCode != 0 {
			assert.Equal(
				t,
				reqCfg.ExpectedCode,
				status,
				"case %d, expected status code: %d, got: %d",
				idx,
				reqCfg.ExpectedCode,
				status,
			)
		}

		if reqCfg.ExpectedLocation != "" {
			loc, _ := url.Parse(resp.Header().Get("Location"))
			assert.True(
				t,
				strings.Contains(
					loc.String(),
					reqCfg.ExpectedLocation,
				),
				"expected location to contain %s",
				loc.String(),
			)

			if loc.Query().Get("state") != "" {
				state, err := uuid.FromString(loc.Query().Get("state"))

				if err != nil {
					assert.Fail(
						t,
						"expected state parameter with valid UUID, got: %s with error %s",
						state.String(),
						err,
					)
				}
			}
		}

		if len(reqCfg.ExpectedHeaders) > 0 {
			for headerName, expVal := range reqCfg.ExpectedHeaders {
				realVal := resp.Header().Get(headerName)

				assert.Equal(
					t,
					expVal,
					realVal,
					"case %d, expected header %s=%s, got: %s",
					idx,
					headerName,
					expVal,
					realVal,
				)
			}
		}

		if reqCfg.ExpectedProxy {
			assert.NotEmpty(
				t,
				resp.Header().Get(testProxyAccepted),
				"case %d, did not proxy request",
				idx,
			)
		} else {
			assert.Empty(
				t,
				resp.Header().Get(testProxyAccepted),
				"case %d, should NOT proxy request",
				idx,
			)
		}

		if reqCfg.ExpectedProxyHeaders != nil && len(reqCfg.ExpectedProxyHeaders) > 0 {
			for headerName, headerVal := range reqCfg.ExpectedProxyHeaders {
				headers := upstream.Headers

				switch headerVal {
				case "":
					assert.NotEmpty(
						t,
						headers.Get(headerName),
						"case %d, expected the proxy header: %s to exist",
						idx,
						headerName,
					)
				default:
					assert.Equal(
						t,
						headerVal,
						headers.Get(headerName),
						"case %d, expected proxy header %s=%s, got: %s",
						idx,
						headerName,
						headerVal,
						headers.Get(headerName),
					)
				}
			}
		}

		if reqCfg.ExpectedProxyHeadersValidator != nil &&
			len(reqCfg.ExpectedProxyHeadersValidator) > 0 {
			// comment
			for headerName, headerValidator := range reqCfg.ExpectedProxyHeadersValidator {
				headers := upstream.Headers
				switch headerValidator {
				case nil:
					assert.NotNil(
						t,
						headerValidator,
						"Validation function is nil, forgot to configure?",
					)
				default:
					headerValidator(t, f.config, headers.Get(headerName))
				}
			}
		}

		if len(reqCfg.ExpectedNoProxyHeaders) > 0 {
			for _, headerName := range reqCfg.ExpectedNoProxyHeaders {
				assert.Empty(
					t,
					upstream.Headers.Get(headerName),
					"case %d, header: %s was not expected to exist",
					idx,
					headerName,
				)
			}
		}

		if reqCfg.ExpectedContent != nil {
			e := string(resp.Body())
			reqCfg.ExpectedContent(e, idx)
		}

		if reqCfg.ExpectedContentContains != "" {
			body := string(resp.Body())

			assert.Contains(
				t,
				body,
				reqCfg.ExpectedContentContains,
				"case %d, expected content: %s, got: %s",
				idx,
				reqCfg.ExpectedContentContains,
				body,
			)
		}

		if len(reqCfg.ExpectedCookies) > 0 {
			for cookName, expVal := range reqCfg.ExpectedCookies {
				cookie := findCookie(cookName, resp.Cookies())

				if !assert.NotNil(
					t,
					cookie,
					"case %d, expected cookie %s not found",
					idx,
					cookName,
				) {
					continue
				}

				if expVal != "" {
					assert.Equal(
						t,
						cookie.Value,
						expVal,
						"case %d, expected cookie value: %s, got: %s",
						idx,
						expVal,
						cookie.Value,
					)
				}
			}
		}

		if len(reqCfg.ExpectedCookiesValidator) > 0 {
			for cookName, cookValidator := range reqCfg.ExpectedCookiesValidator {
				cookie := findCookie(cookName, resp.Cookies())

				if !assert.NotNil(
					t,
					cookie,
					"case %d, expected cookie %s not found",
					idx,
					cookName,
				) {
					continue
				}

				if cookValidator != nil {
					assert.True(
						t,
						cookValidator(t, f.config, cookie.Value),
						"case %d, invalid cookie value: %s in expected cookie validator",
						idx,
						cookie.Value,
					)
				}
			}
		}

		if len(reqCfg.ExpectedLoginCookiesValidator) > 0 {
			for cookName, cookValidator := range reqCfg.ExpectedLoginCookiesValidator {
				cookie, ok := f.cookies[cookName]

				if !assert.True(t, ok, "case %d, expected cookie %s not found", idx, cookName) {
					continue
				}

				if cookValidator != nil {
					assert.True(
						t,
						cookValidator(t, f.config, cookie.Value),
						"case %d, invalid cookie value in login cookie validator: %s",
						idx,
						cookie.Value,
					)
				}
			}
		}

		if reqCfg.OnResponse != nil {
			reqCfg.OnResponse(idx, request, resp)
		}
	}
}

func (f *fakeProxy) performUserLogin(uri string) error {
	resp, flowCookies, err := makeTestCodeFlowLogin(f.getServiceURL() + uri)
	if err != nil {
		return err
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == f.config.CookieAccessName || cookie.Name == f.config.CookieRefreshName {
			f.cookies[cookie.Name] = &http.Cookie{
				Name:   cookie.Name,
				Path:   "/",
				Domain: "127.0.0.1",
				Value:  cookie.Value,
			}
		}
	}

	for i, cook := range flowCookies {
		f.cookies[cook.Name] = flowCookies[i]
	}

	defer resp.Body.Close()

	return nil
}

func setRequestAuthentication(cfg *Config, client *resty.Client, request *resty.Request, c *fakeRequest, token string) {
	switch c.HasCookieToken {
	case true:
		client.SetCookie(&http.Cookie{
			Name:  cfg.CookieAccessName,
			Path:  "/",
			Value: token,
		})
	default:
		request.SetAuthToken(token)
	}
}

func newTestService() string {
	_, _, u := newTestProxyService(nil)
	return u
}

func newTestProxyService(config *Config) (*oauthProxy, *fakeAuthServer, string) {
	if config == nil {
		config = newFakeKeycloakConfig()
	}

	authConfig := &fakeAuthConfig{}
	if config.SkipOpenIDProviderTLSVerify {
		authConfig.EnableTLS = true
	}

	auth := newFakeAuthServer(authConfig)

	config.DiscoveryURL = auth.getLocation()
	config.RevocationEndpoint = auth.getRevocationURL()
	config.Verbose = false
	config.EnableLogging = false
	err := config.update()

	if err != nil {
		panic("failed to create proxy service, error: " + err.Error())
	}

	proxy, err := newProxy(config)
	if err != nil {
		panic("failed to create proxy service, error: " + err.Error())
	}

	// step: create an fake upstream endpoint
	proxy.upstream = new(fakeUpstreamService)
	service := httptest.NewServer(proxy.router)
	config.RedirectionURL = service.URL

	// step: we need to update the client config
	if proxy.provider, proxy.idpClient, err = proxy.newOpenIDProvider(); err != nil {
		panic("failed to recreate the openid client, error: " + err.Error())
	}

	return proxy, auth, service.URL
}

func newFakeHTTPRequest(method, path string) *http.Request {
	return &http.Request{
		Method: method,
		Header: make(map[string][]string),
		Host:   "127.0.0.1",
		URL: &url.URL{
			Scheme: "http",
			Host:   "127.0.0.1",
			Path:   path,
		},
	}
}

func newFakeKeycloakConfig() *Config {
	return &Config{
		ClientID:                    fakeClientID,
		ClientSecret:                fakeSecret,
		CookieAccessName:            "kc-access",
		CookieRefreshName:           "kc-state",
		DisableAllLogging:           true,
		DiscoveryURL:                "127.0.0.1:0",
		EnableAuthorizationCookies:  true,
		EnableAuthorizationHeader:   true,
		EnableLogging:               false,
		EnableLoginHandler:          true,
		EnableTokenHeader:           true,
		EnableCompression:           false,
		EnableMetrics:               false,
		Listen:                      "127.0.0.1:0",
		ListenAdmin:                 "",
		ListenAdminScheme:           "http",
		TLSAdminCertificate:         "",
		TLSAdminPrivateKey:          "",
		TLSAdminCaCertificate:       "",
		OAuthURI:                    "/oauth",
		OpenIDProviderTimeout:       time.Second * 5,
		SkipOpenIDProviderTLSVerify: false,
		SkipUpstreamTLSVerify:       false,
		Scopes:                      []string{},
		Verbose:                     false,
		Resources: []*Resource{
			{
				URL:     fakeAdminRoleURL,
				Methods: []string{"GET"},
				Roles:   []string{fakeAdminRole},
			},
			{
				URL:     fakeTestRoleURL,
				Methods: []string{"GET"},
				Roles:   []string{fakeTestRole},
			},
			{
				URL:     fakeTestAdminRolesURL,
				Methods: []string{"GET"},
				Roles:   []string{fakeAdminRole, fakeTestRole},
			},
			{
				URL:     fakeAuthAllURL,
				Methods: allHTTPMethods,
				Roles:   []string{},
			},
			{
				URL:         fakeTestWhitelistedURL,
				WhiteListed: true,
				Methods:     allHTTPMethods,
				Roles:       []string{},
			},
		},
	}
}

func makeTestCodeFlowLogin(location string) (*http.Response, []*http.Cookie, error) {
	flowCookies := make([]*http.Cookie, 0)

	uri, err := url.Parse(location)

	if err != nil {
		return nil, nil, err
	}
	// step: get the redirect
	var resp *http.Response
	for count := 0; count < 4; count++ {
		req, err := http.NewRequest(http.MethodGet, location, nil)

		if err != nil {
			return nil, nil, err
		}

		if resp != nil {
			cookies := resp.Cookies()
			flowCookies = append(flowCookies, cookies...)
		}

		// step: make the request
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				//nolint:gas
				InsecureSkipVerify: true,
			},
		}

		resp, err = transport.RoundTrip(req)

		if err != nil {
			return nil, nil, err
		}

		if resp.StatusCode != http.StatusSeeOther {
			return nil, nil, fmt.Errorf("no redirection found in resp, status code %d", resp.StatusCode)
		}

		location = resp.Header.Get("Location")

		if !strings.HasPrefix(location, "http") && !strings.HasPrefix(location, "https") {
			location = fmt.Sprintf("%s://%s%s", uri.Scheme, uri.Host, location)
		}
	}
	return resp, flowCookies, nil
}

// fakeUpstreamResponse is the response from fake upstream
type fakeUpstreamResponse struct {
	URI     string      `json:"uri"`
	Method  string      `json:"method"`
	Address string      `json:"address"`
	Headers http.Header `json:"headers"`
}

// fakeUpstreamService acts as a fake upstream service, returns the headers and request
type fakeUpstreamService struct{}

func (f *fakeUpstreamService) ServeHTTP(wrt http.ResponseWriter, req *http.Request) {
	wrt.Header().Set(testProxyAccepted, "true")

	upgrade := strings.ToLower(req.Header.Get("Upgrade"))
	if upgrade == "websocket" {
		websocket.Handler(func(wsock *websocket.Conn) {
			defer wsock.Close()
			var data []byte
			err := websocket.Message.Receive(wsock, &data)
			if err != nil {
				wsock.WriteClose(http.StatusBadRequest)
				return
			}
			content, _ := json.Marshal(&fakeUpstreamResponse{
				URI:     req.RequestURI,
				Method:  req.Method,
				Address: req.RemoteAddr,
				Headers: req.Header,
			})
			_ = websocket.Message.Send(wsock, content)
		}).ServeHTTP(wrt, req)
	} else {
		wrt.Header().Set("Content-Type", "application/json")
		content, err := json.Marshal(&fakeUpstreamResponse{
			// r.RequestURI is what was received by the proxy.
			// r.URL.String() is what is actually sent to the upstream service.
			// KEYCLOAK-10864, KEYCLOAK-11276, KEYCLOAK-13315
			URI:     req.URL.String(),
			Method:  req.Method,
			Address: req.RemoteAddr,
			Headers: req.Header,
		})

		if err != nil {
			wrt.WriteHeader(http.StatusInternalServerError)
		} else {
			wrt.WriteHeader(http.StatusOK)
		}

		_, _ = wrt.Write(content)
	}
}

type fakeToken struct {
	claims DefaultTestTokenClaims
}

func newTestToken(issuer string) *fakeToken {
	claims := defTestTokenClaims
	claims.Exp = time.Now().Add(1 * time.Hour).Unix()
	claims.Iat = time.Now().Unix()
	claims.Iss = issuer

	return &fakeToken{claims: claims}
}

// getToken returns a JWT token from the clains
func (t *fakeToken) getToken() (string, error) {
	input := []byte("")
	block, _ := pem.Decode([]byte(fakePrivateKey))
	if block != nil {
		input = block.Bytes
	}

	var priv interface{}
	priv, err0 := x509.ParsePKCS8PrivateKey(input)

	if err0 != nil {
		return "", err0
	}

	alg := jose2.SignatureAlgorithm("RS256")
	privKey := &jose2.JSONWebKey{Key: priv, Algorithm: string(alg), KeyID: "test-kid"}
	signer, err := jose2.NewSigner(jose2.SigningKey{Algorithm: alg, Key: privKey}, nil)

	if err != nil {
		return "", err
	}

	b := jwt.Signed(signer).Claims(&t.claims)
	jwt, err := b.CompactSerialize()

	if err != nil {
		return "", err
	}

	return jwt, nil
}

// getUnsignedToken returns a unsigned JWT token from the clains
func (t *fakeToken) getUnsignedToken() (string, error) {
	input := []byte("")
	block, _ := pem.Decode([]byte(fakePrivateKey))
	if block != nil {
		input = block.Bytes
	}

	var priv interface{}
	priv, err0 := x509.ParsePKCS8PrivateKey(input)

	if err0 != nil {
		return "", err0
	}

	alg := jose2.SignatureAlgorithm("RS256")
	privKey := &jose2.JSONWebKey{Key: priv, Algorithm: string(alg), KeyID: ""}
	signer, err := jose2.NewSigner(jose2.SigningKey{Algorithm: alg, Key: privKey}, nil)

	if err != nil {
		return "", err
	}

	b := jwt.Signed(signer).Claims(&t.claims)
	jwt, err := b.CompactSerialize()

	if err != nil {
		return "", err
	}

	items := strings.Split(jwt, ".")
	jwt = strings.Join(items[0:1], ".")

	return jwt, nil
}

// setExpiration sets the expiration of the token
func (t *fakeToken) setExpiration(tm time.Time) {
	t.claims.Exp = tm.Unix()
}

// addGroups adds groups to then token
func (t *fakeToken) addGroups(groups []string) {
	t.claims.Groups = groups
}

// addRealmRoles adds realms roles to token
func (t *fakeToken) addRealmRoles(roles []string) {
	t.claims.RealmAccess.Roles = roles
}

// addClientRoles adds client roles to the token
func (t *fakeToken) addClientRoles(client string, roles []string) {
	t.claims.ResourceAccess = make(map[string]RoleClaim)
	t.claims.ResourceAccess[client] = RoleClaim{Roles: roles}
}

type fakeAuthServer struct {
	location                  *url.URL
	proxyLocation             string
	key                       jose2.JSONWebKey
	server                    *httptest.Server
	expiration                time.Duration
	resourceSetHandlerFailure bool
}

const fakePrivateKey = `
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0E2cxe1nDLCE7
U4k3Zvd4nMiAHqKZBxCPuADbzR15IcOlcLTqBBPNCpwgXSZwobgeEl1aDi9fAsEK
XZNPU2GbIPmw5nBHfE/RZ5JmU2GXdEm2R2Irnwpi8kk8hHWPK4ETN8+6yk4qKF1P
xkoHIilm37T8zWoqzYtIuj3/Obqi3Io67pvKYCsA1qMR3RRlI9IegUAc3WHMrKIL
YQShEo66pg8cTb7Q/LdgaSxR3KLi9eox0vTE72AmVQoBZlZ/ej7sJpwPKKmkszXU
AMPGf1s3Hx/lgDtM3MxtHk0pxLBHgP+P5i77dF9edW9hc/fMirdOmCpYZboox3Lr
IGoVcJodAgMBAAECggEAahX4OEV0BzArT7kR4GqvpgWvdRMXNVHdJt3+237GO0Nx
8DgqzKakR6pVeheGeto7DrRA/LnYnH+R3Bpum1AC85IEp3vKb8LDfxkmPVQn7ULb
3h/FrO8f/lTAYn+ihjrZ6sl5fpCKZfmrp0CpAfTVMT7fcANP5XF7+deGiKKo2iJW
g1O8ZflihEDclPtqBABpRjBejRiv+7YUR/8HeqNUjmLEWGwAHEqrsFwMz92CvJd+
N9U03Cs1LvpXkIXHG84SUvbDQRuyxoONXKauasYr01kMFqBTjOc86xXSNsMWCzu4
UaWB1ZtMugNjyMNdVQUSLz1EABI4aQhWptmJud4LwQKBgQDuq3L3gOEaCmi4+46B
vnHdu0j6shULDdjxb4r8xY4tf4T8c+/4Lm/siM2+Fb+g01OECVRPVQlFd0inoTy+
j8ARveuRvrrGzAS5CB1tl+PiLJ5HbdltzTrV3ZUb99fvbnHAi7up7daZg9IBfc1n
ABWTA1pdOzK82g8qDeFBMSCJUQKBgQDBJsVvbheKL2xdKyIzd2je3gwInkYpAUqa
S9zS6h5wpG8TqFt90OYvmawyvTwspgp3nUUHTv9Z5FChFPgtoZJJO/0OYt6DjpUs
Ohg3DhthG5q6fG+kS2zGGHxQSCzQB6CvKdeZ5iMO/L0arKs9UuIdLV/SNfMdKm6v
8tdcYCdRDQKBgQC5cCzbcR91BDFpyMpotHf0N9f0MPl4pUGyFWCAFV7qqvHA1LPW
uP3tYj25O1ywsIFrTXRcT03s00l4NSblSPuKzW2CyBaG722b9lonFKTSzqgMB6Ww
Uo0sLgX0vRThy4ZGfEtLNKhQjsNUtVIqfT5GA4zqc1xwr1yo6C/kXy9QgQKBgQCX
Vh552WOeRNv9/+7TLms/u/Dny8MjG7ztOiVyKDfjgCL73vyYjtXcU+ak9rowLYSk
BdhxCoduUkKOg5SUhDTPJq522CaKI2xj87zHXkk7g9pu5VLAAszeRY8ZhAOAl4lh
1UH1dmjftE0imkmtScSaodOjK9wpbPa+62GsIjaL/QKBgFdwyRTp7GzbTDsQ94bA
u6MoFT7Ln2I48zaA07G76r9t3oOAsO8doED+hdSwlzA7RyM2l6jOkJli+NXmVA1G
eJN9LU6cvrgsyw2XF54Zi+sRdXb1LU9pVHcINIOwY7zNMvYRAkStkxhPXUDBinxo
wqVzh3GBBzPxAb3aM8Tu0W+1
-----END PRIVATE KEY-----
`

const fakeCert = `
-----BEGIN CERTIFICATE-----
MIIDXjCCAkagAwIBAgIUVUN+CQWv4afaLwWyBYA3hzYUK1UwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMTAzMTcyMzU2NDFaFw00MTAz
MTIyMzU2NDFaMHgxCzAJBgNVBAYTAlhYMQwwCgYDVQQIDANOL0ExDDAKBgNVBAcM
A04vQTEgMB4GA1UECgwXU2VsZi1zaWduZWQgY2VydGlmaWNhdGUxKzApBgNVBAMM
IjEyMC4wLjAuMTogU2VsZi1zaWduZWQgY2VydGlmaWNhdGUwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC0E2cxe1nDLCE7U4k3Zvd4nMiAHqKZBxCPuADb
zR15IcOlcLTqBBPNCpwgXSZwobgeEl1aDi9fAsEKXZNPU2GbIPmw5nBHfE/RZ5Jm
U2GXdEm2R2Irnwpi8kk8hHWPK4ETN8+6yk4qKF1PxkoHIilm37T8zWoqzYtIuj3/
Obqi3Io67pvKYCsA1qMR3RRlI9IegUAc3WHMrKILYQShEo66pg8cTb7Q/LdgaSxR
3KLi9eox0vTE72AmVQoBZlZ/ej7sJpwPKKmkszXUAMPGf1s3Hx/lgDtM3MxtHk0p
xLBHgP+P5i77dF9edW9hc/fMirdOmCpYZboox3LrIGoVcJodAgMBAAGjEzARMA8G
A1UdEQQIMAaHBH8AAAEwDQYJKoZIhvcNAQELBQADggEBAIyJDSwNHcr6xstklu/K
HypaivAFa95eAI1QrCsJF1V/mm9LEEGes/iHbvkpFJHQKhJkO6aoQmek8zF2wKc/
3RhnxrR32/ujHetJFka/LtvytVhXoSqkUWeaXOfBOCR/XrwTwRHzbbCNJpUsetXr
9aeDvSrtuB/AaRU2tBlQ9GR1H+CcoBgDmD3IpuKCievvJbmU+KzuW9AUg6d0yLNP
2VtZUA/9JpF9PZOMPw+iOhmjhTqfRD2QvbkR7e34d+1mLBn524KIc8Y2U3OMpDuG
BfVHOQ5JhTNGn9aogxpzF3L9oMUZ+fCbobVyHMMyE6b82H8FUpm1FDJpZaILI5kT
isg=
-----END CERTIFICATE-----
`

const fakeCA = `
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUCDok30ZdCF+fn3KuK/odxYyqJR0wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMTAzMTcyMzM0MTZaFw00MTAz
MTIyMzM0MTZaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDVwtjZoJiDALDrovZviHWRhCgPXBxaLYoi5d3sa1UX
F28fEHHcqHChMHng0XmQDwBRvdGXfEL+d+TyOk6H2EfC5YzF4BFA9jEuX/xvINWd
STYFkq4uqjFVl5/1WA6fme0UfpIT+BNSqMufH1Q63rBMgZmQS10/mYBWMXzW9MpC
Mc/VqGiNfVD1fGf3d86gmteHPSR0yABeIyF3BhWkea50sNu7jz7Vw65OdAZxuw9W
o0UGT0Bc2ml8clnkhnXipvyYUJQqVgyCcFsI5rc5Gsie8rJ36LyZsf3nnGF56hjw
i49YmH3z0xl70XUIxkm2o2h55P5tgA5KauZB3v0mFuTxAgMBAAGjUzBRMB0GA1Ud
DgQWBBQ5Fw8voBMO1GoQl1Qqm5UdFzbuHDAfBgNVHSMEGDAWgBQ5Fw8voBMO1GoQ
l1Qqm5UdFzbuHDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDU
msNwnbl8uI4VcFsiyrNS7Np2xLmcs6LgCfP9WzsA4h6Ag2K15d9eh+CgaL59oza8
q0pxRcasLFtuk0egRc+HwNR5ynwt4W2al4zB1dRpTWgrnNaoOBdhsb3ifNEjFcYD
di+dPoKLST6xqKGh0zl+W4FLevUDg7KzJVcttaQ8tFh5KafcmSHZ7PfNbFsfbx/R
wthh/acHnCkOndcTBEoHdIv283bONr1Zpe9Sok2mM3uVsCvv6fRYnG+mRqcZ3C9d
hHbOowWOqA2rxWxSHrkBTQju/uYQKG5GMnXWgZokUgwRDMaNMpdp03GG4Bgeg/06
8cad+/Bp0tBaKmnCtxOC
-----END CERTIFICATE-----
`

type fakeOidcDiscoveryResponse struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

type fakeAuthConfig struct {
	EnableTLS                 bool
	EnableProxy               bool
	Expiration                time.Duration
	ResourceSetHandlerFailure bool
}

// newFakeAuthServer simulates a oauth service
func newFakeAuthServer(config *fakeAuthConfig) *fakeAuthServer {
	certBlock, _ := pem.Decode([]byte(fakeCert))

	var cert *x509.Certificate
	cert, err := x509.ParseCertificate(certBlock.Bytes)

	if err != nil {
		panic("failed to parse certificate from block, error: " + err.Error())
	}

	x5tSHA1 := sha1.Sum(cert.Raw)
	x5tSHA256 := sha256.Sum256(cert.Raw)

	service := &fakeAuthServer{
		key: jose2.JSONWebKey{
			Key:                         cert.PublicKey,
			KeyID:                       "test-kid",
			Algorithm:                   "RS256",
			Certificates:                []*x509.Certificate{cert},
			CertificateThumbprintSHA1:   x5tSHA1[:],
			CertificateThumbprintSHA256: x5tSHA256[:],
		},
	}

	router := chi.NewRouter()
	router.Use(middleware.Recoverer)
	router.Get("/auth/realms/hod-test/.well-known/openid-configuration", service.discoveryHandler)
	router.Get("/auth/realms/hod-test/protocol/openid-connect/certs", service.keysHandler)
	router.Get("/auth/realms/hod-test/protocol/openid-connect/token", service.tokenHandler)
	router.Get("/auth/realms/hod-test/protocol/openid-connect/auth", service.authHandler)
	router.Get("/auth/realms/hod-test/protocol/openid-connect/userinfo", service.userInfoHandler)
	router.Post("/auth/realms/hod-test/protocol/openid-connect/logout", service.logoutHandler)
	router.Post("/auth/realms/hod-test/protocol/openid-connect/revoke", service.revocationHandler)
	router.Post("/auth/realms/hod-test/protocol/openid-connect/token", service.tokenHandler)
	router.Get("/auth/realms/hod-test/authz/protection/resource_set", service.ResourcesHandler)
	router.Get("/auth/realms/hod-test/authz/protection/resource_set/{id}", service.ResourceHandler)
	router.Post("/auth/realms/hod-test/authz/protection/permission", service.PermissionTicketHandler)

	if config.EnableTLS {
		service.server = httptest.NewTLSServer(router)
	} else {
		service.server = httptest.NewServer(router)
	}

	if config.EnableProxy {
		delay := time.Duration(0) * time.Second
		proxy := relay.NewProxy(delay, service.server)
		service.proxyLocation = proxy.URL
	}

	location, err := url.Parse(service.server.URL)
	if err != nil {
		panic("unable to create fake oauth service, error: " + err.Error())
	}
	service.location = location
	service.resourceSetHandlerFailure = config.ResourceSetHandlerFailure

	service.expiration = time.Duration(1) * time.Hour

	if config.Expiration.Seconds() > 0 {
		service.expiration = config.Expiration
	}

	return service
}

func (r *fakeAuthServer) Close() {
	r.server.Close()
}

func (r *fakeAuthServer) getProxyURL() string {
	return r.proxyLocation
}

func (r *fakeAuthServer) getLocation() string {
	return fmt.Sprintf("%s://%s/auth/realms/hod-test", r.location.Scheme, r.location.Host)
}

func (r *fakeAuthServer) getRevocationURL() string {
	return fmt.Sprintf("%s://%s/auth/realms/hod-test/protocol/openid-connect/revoke", r.location.Scheme, r.location.Host)
}

func (r *fakeAuthServer) setTokenExpiration(tm time.Duration) *fakeAuthServer {
	r.expiration = tm
	return r
}

func (r *fakeAuthServer) discoveryHandler(w http.ResponseWriter, req *http.Request) {
	renderJSON(http.StatusOK, w, req, fakeOidcDiscoveryResponse{
		Issuer:      fmt.Sprintf("%s://%s/auth/realms/hod-test", r.location.Scheme, r.location.Host),
		AuthURL:     fmt.Sprintf("%s://%s/auth/realms/hod-test/protocol/openid-connect/auth", r.location.Scheme, r.location.Host),
		TokenURL:    fmt.Sprintf("%s://%s/auth/realms/hod-test/protocol/openid-connect/token", r.location.Scheme, r.location.Host),
		JWKSURL:     fmt.Sprintf("%s://%s/auth/realms/hod-test/protocol/openid-connect/certs", r.location.Scheme, r.location.Host),
		UserInfoURL: fmt.Sprintf("%s://%s/auth/realms/hod-test/protocol/openid-connect/userinfo", r.location.Scheme, r.location.Host),
		Algorithms:  []string{"RS256"},
	})
}

func (r *fakeAuthServer) keysHandler(w http.ResponseWriter, req *http.Request) {
	renderJSON(http.StatusOK, w, req, jose2.JSONWebKeySet{Keys: []jose2.JSONWebKey{r.key}})
}

func (r *fakeAuthServer) authHandler(wrt http.ResponseWriter, req *http.Request) {
	state := req.URL.Query().Get("state")
	redirect := req.URL.Query().Get("redirect_uri")
	if redirect == "" {
		wrt.WriteHeader(http.StatusInternalServerError)
		return
	}
	if state == "" {
		state = "/"
	}

	randString, err := getRandomString(32)

	if err != nil {
		wrt.WriteHeader(http.StatusInternalServerError)
		return
	}

	redirectionURL := fmt.Sprintf("%s?state=%s&code=%s", redirect, state, randString)

	http.Redirect(wrt, req, redirectionURL, http.StatusSeeOther)
}

func (r *fakeAuthServer) logoutHandler(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (r *fakeAuthServer) revocationHandler(wrt http.ResponseWriter, req *http.Request) {
	// according RFC revocation endpoint can be access/refresh token, keycloak
	// implementation https://github.com/keycloak/keycloak/pull/6704, accepts
	// refresh/offline tokens
	if token := req.FormValue("token"); token == "" {
		wrt.WriteHeader(http.StatusBadRequest)
		return
	}

	wrt.WriteHeader(http.StatusOK)
}

func (r *fakeAuthServer) userInfoHandler(wrt http.ResponseWriter, req *http.Request) {
	items := strings.Split(req.Header.Get("Authorization"), " ")
	if len(items) != 2 {
		wrt.WriteHeader(http.StatusUnauthorized)
		return
	}

	token, err := jwt.ParseSigned(items[1])

	if err != nil {
		wrt.WriteHeader(http.StatusUnauthorized)
		return
	}

	user, err := extractIdentity(token)

	if err != nil {
		wrt.WriteHeader(http.StatusUnauthorized)
		return
	}

	renderJSON(http.StatusOK, wrt, req, map[string]interface{}{
		"sub":                user.claims["sub"],
		"name":               user.claims["name"],
		"given_name":         user.claims["given_name"],
		"family_name":        user.claims["familty_name"],
		"preferred_username": user.claims["preferred_username"],
		"email":              user.claims["email"],
		"picture":            user.claims["picture"],
	})
}

//nolint:cyclop
func (r *fakeAuthServer) tokenHandler(writer http.ResponseWriter, req *http.Request) {
	expires := time.Now().Add(r.expiration)
	refreshExpires := time.Now().Add(2 * r.expiration)
	token := newTestToken(r.getLocation())
	token.setExpiration(expires)
	refreshToken := newTestToken(r.getLocation())
	refreshToken.setExpiration(refreshExpires)

	if req.FormValue("grant_type") == GrantTypeUmaTicket {
		token.claims.Authorization = authorization.Permissions{
			Permissions: []authorization.Permission{
				{
					Scopes:       []string{"test"},
					ResourceID:   "6ef1b62e-0fd4-47f2-81fc-eead97a01c22",
					ResourceName: "some",
				},
			},
		}
	}

	// sign the token with the private key
	jwtAccess, err := token.getToken()
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	// sign the token with the private key
	jwtRefresh, err := refreshToken.getToken()
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch req.FormValue("grant_type") {
	case GrantTypeUserCreds:
		username := req.FormValue("username")
		password := req.FormValue("password")

		if username == "" || password == "" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		if username == validUsername && password == validPassword {
			renderJSON(http.StatusOK, writer, req, tokenResponse{
				IDToken:      jwtAccess,
				AccessToken:  jwtAccess,
				RefreshToken: jwtRefresh,
				ExpiresIn:    float64(expires.UTC().Second()),
			})
			return
		}

		renderJSON(http.StatusUnauthorized, writer, req, map[string]string{
			"error":             "invalid_grant",
			"error_description": "invalid user credentials",
		})
	case GrantTypeClientCreds:
		clientID := req.FormValue("client_id")
		clientSecret := req.FormValue("client_secret")

		if clientID == "" || clientSecret == "" {
			u, p, ok := req.BasicAuth()
			clientID = u
			clientSecret = p

			if clientID == "" || clientSecret == "" || !ok {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		}

		if clientID == validUsername && clientSecret == validPassword {
			renderJSON(http.StatusOK, writer, req, tokenResponse{
				IDToken:      jwtAccess,
				AccessToken:  jwtAccess,
				RefreshToken: jwtRefresh,
				ExpiresIn:    float64(expires.UTC().Second()),
			})
			return
		}

		renderJSON(http.StatusUnauthorized, writer, req, map[string]string{
			"error":             "invalid_grant",
			"error_description": "invalid client credentials",
		})
	case GrantTypeRefreshToken:
		oldRefreshToken, err := jwt.ParseSigned(req.FormValue("refresh_token"))

		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		stdClaims := &jwt.Claims{}

		err = oldRefreshToken.UnsafeClaimsWithoutVerification(stdClaims)

		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		expiration := time.Until(stdClaims.Expiry.Time())

		if expiration <= 0 {
			type ExpiredRefresh struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			}

			expRefresh := ExpiredRefresh{"invalid_grant", "Token is not active"}
			respBody, err := json.Marshal(expRefresh)

			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}

			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write(respBody)

			return
		}

		renderJSON(http.StatusOK, writer, req, tokenResponse{
			IDToken:     jwtAccess,
			AccessToken: jwtAccess,
			ExpiresIn:   float64(expires.Second()),
		})
	case GrantTypeAuthCode:
		renderJSON(http.StatusOK, writer, req, tokenResponse{
			IDToken:      jwtAccess,
			AccessToken:  jwtAccess,
			RefreshToken: jwtRefresh,
			ExpiresIn:    float64(expires.Second()),
		})
	case GrantTypeUmaTicket:
		renderJSON(http.StatusOK, writer, req, tokenResponse{
			IDToken:      jwtAccess,
			AccessToken:  jwtAccess,
			RefreshToken: jwtRefresh,
			ExpiresIn:    float64(expires.Second()),
		})
	default:
		writer.WriteHeader(http.StatusBadRequest)
	}
}

func (r *fakeAuthServer) ResourcesHandler(w http.ResponseWriter, req *http.Request) {
	response := []string{"6ef1b62e-0fd4-47f2-81fc-eead97a01c22"}
	renderJSON(http.StatusOK, w, req, response)
}

func (r *fakeAuthServer) ResourceHandler(wrt http.ResponseWriter, req *http.Request) {
	if r.resourceSetHandlerFailure {
		renderJSON(http.StatusNotFound, wrt, req, []string{})
	}

	type Resource struct {
		Name               string              `json:"name"`
		Type               string              `json:"type"`
		Owner              struct{ ID string } `json:"owner"`
		OwnerManagedAccess bool                `json:"ownerManagedAccess"`
		Attributes         struct{}            `json:"attributes"`
		ID                 string              `json:"_id"`
		URIS               []string            `json:"uris"`
		ResourceScopes     []struct {
			Name string `json:"name"`
		} `json:"resource_scopes"`
		Scopes []struct {
			Name string `json:"name"`
		} `json:"scopes"`
	}

	response := Resource{
		Name:               "Default Resource",
		Type:               "urn:test-client:resources:default",
		Owner:              struct{ ID string }{ID: "6ef1b62e-0fd4-47f2-81fc-eead97a01c22"},
		OwnerManagedAccess: false,
		Attributes:         struct{}{},
		ID:                 "6ef1b62e-0fd4-47f2-81fc-eead97a01c22",
		URIS:               []string{"/*"},
		ResourceScopes: []struct {
			Name string `json:"name"`
		}{{Name: "test"}},
		Scopes: []struct {
			Name string `json:"name"`
		}{{Name: "test"}},
	}
	renderJSON(http.StatusOK, wrt, req, response)
}

func (r *fakeAuthServer) PermissionTicketHandler(wrt http.ResponseWriter, req *http.Request) {
	token := newTestToken(r.getLocation())
	acc, err := token.getToken()

	if err != nil {
		wrt.WriteHeader(http.StatusInternalServerError)
		return
	}

	type Ticket struct {
		Ticket string `json:"ticket"`
	}

	response := Ticket{
		Ticket: acc,
	}
	renderJSON(http.StatusOK, wrt, req, response)
}

func getRandomString(n int) (string, error) {
	runes := make([]rune, n)
	for idx := range runes {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(n)))

		if err != nil {
			return "", err
		}

		runes[idx] = letterRunes[num.Int64()]
	}
	return string(runes), nil
}

func renderJSON(code int, w http.ResponseWriter, req *http.Request, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
