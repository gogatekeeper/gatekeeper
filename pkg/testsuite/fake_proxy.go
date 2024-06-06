package testsuite

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/gofrs/uuid"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/keycloak/config"
	"github.com/gogatekeeper/gatekeeper/pkg/keycloak/proxy"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/cookie"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"github.com/oleiade/reflections"
	"github.com/stoewer/go-strcase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRequest struct {
	BasicAuth                     bool
	Cookies                       []*http.Cookie
	Expires                       time.Duration
	FormValues                    map[string]string
	Groups                        []string
	HasCookieToken                bool
	HasLogin                      bool
	LoginXforwarded               bool
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
	TokenAuthorization            *models.Permissions
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
	ExpectedHeadersValidator      map[string]func(*testing.T, *config.Config, string)
	ExpectedLocation              string
	ExpectedNoProxyHeaders        []string
	ExpectedProxy                 bool
	ExpectedProxyHeaders          map[string]string
	ExpectedProxyHeadersValidator map[string]func(*testing.T, *config.Config, string)
	ExpectedCookiesValidator      map[string]func(*testing.T, *config.Config, string) bool
	ExpectedLoginCookiesValidator map[string]func(*testing.T, *config.Config, string) bool
}

type fakeProxy struct {
	config  *config.Config
	idp     *fakeAuthServer
	proxy   *proxy.OauthProxy
	cookies map[string]*http.Cookie
}

func newFakeProxy(cfg *config.Config, authConfig *fakeAuthConfig) *fakeProxy {
	log.SetOutput(io.Discard)

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
	err := cfg.Update()
	if err != nil {
		panic(errors.Join(ErrCreateFakeProxy, err).Error())
	}

	var oProxy *proxy.OauthProxy
	if cfg.Upstream == "" {
		oProxy, err = proxy.NewProxy(cfg, nil, &FakeUpstreamService{})
	} else {
		oProxy, err = proxy.NewProxy(cfg, nil, nil)
	}
	if err != nil {
		panic(errors.Join(ErrCreateFakeProxy, err).Error())
	}

	// proxy.log = zap.NewNop()
	if err = oProxy.Run(); err != nil {
		panic("failed to create the proxy service, error: " + err.Error())
	}

	cfg.RedirectionURL = fmt.Sprintf("http://%s", oProxy.Listener.Addr().String())

	return &fakeProxy{cfg, auth, oProxy, make(map[string]*http.Cookie)}
}

func (f *fakeProxy) getServiceURL() string {
	return fmt.Sprintf("http://%s", f.proxy.Listener.Addr().String())
}

// RunTests performs a series of requests against a fake proxy service
//
//nolint:gocyclo,funlen,cyclop
func (f *fakeProxy) RunTests(t *testing.T, requests []fakeRequest) {
	defer func() {
		f.idp.Close()
		f.proxy.Server.Close()
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
			if err := f.performUserLogin(&reqCfg); err != nil {
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
			token := NewTestToken(f.idp.getLocation())

			if reqCfg.TokenClaims != nil && len(reqCfg.TokenClaims) > 0 {
				for i := range reqCfg.TokenClaims {
					err := reflections.SetField(
						&token.Claims,
						strcase.UpperCamelCase(i),
						reqCfg.TokenClaims[i],
					)
					require.NoError(t, err)
				}
			}

			if len(reqCfg.Roles) > 0 {
				token.addRealmRoles(reqCfg.Roles)
			}

			if len(reqCfg.Groups) > 0 {
				token.addGroups(reqCfg.Groups)
			}

			if reqCfg.Expires > 0 || reqCfg.Expires < 0 {
				token.SetExpiration(time.Now().Add(reqCfg.Expires))
			}

			if reqCfg.TokenAuthorization != nil {
				token.Claims.Authorization = *reqCfg.TokenAuthorization
			}

			if reqCfg.NotSigned {
				authToken, err := token.GetUnsignedToken()
				require.NoError(t, err)
				setRequestAuthentication(f.config, client, request, &reqCfg, authToken)
			} else {
				authToken, err := token.GetToken()
				require.NoError(t, err)
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
				require.NoError(
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

		if reqCfg.ExpectedHeadersValidator != nil &&
			len(reqCfg.ExpectedHeadersValidator) > 0 {
			// comment
			for headerName, headerValidator := range reqCfg.ExpectedHeadersValidator {
				headers := resp.Header()
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

		if reqCfg.ExpectedProxy {
			assert.NotEmpty(
				t,
				resp.Header().Get(TestProxyAccepted),
				"case %d, did not proxy request",
				idx,
			)
		} else {
			assert.Empty(
				t,
				resp.Header().Get(TestProxyAccepted),
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
				cookie := cookie.FindCookie(cookName, resp.Cookies())

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
						expVal,
						cookie.Value,
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
				cookie := cookie.FindCookie(cookName, resp.Cookies())

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

func (f *fakeProxy) performUserLogin(reqCfg *fakeRequest) error {
	userCookies := map[string]bool{
		f.config.CookieAccessName:  true,
		f.config.CookieRefreshName: true,
		f.config.CookieIDTokenName: true,
	}
	resp, flowCookies, err := makeTestCodeFlowLogin(f.getServiceURL()+reqCfg.URI, reqCfg.LoginXforwarded)
	if err != nil {
		return err
	}
	for _, cookie := range resp.Cookies() {
		if _, ok := userCookies[cookie.Name]; ok {
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

func setRequestAuthentication(cfg *config.Config, client *resty.Client, request *resty.Request, c *fakeRequest, token string) {
	switch c.HasCookieToken {
	case true:
		cookies := client.Cookies
		present := false
		for _, cook := range cookies {
			if cook.Name == cfg.CookieAccessName {
				present = true
				cook.Value = token
				cook.Path = "/"
				break
			}
		}
		if !present {
			client.SetCookie(&http.Cookie{
				Name:  cfg.CookieAccessName,
				Path:  "/",
				Value: token,
			})
		}
	default:
		request.SetAuthToken(token)
	}
}

func newTestService() string {
	_, _, u := newTestProxyService(nil)
	return u
}

func newTestProxyService(config *config.Config) (*proxy.OauthProxy, *fakeAuthServer, string) {
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
	err := config.Update()

	if err != nil {
		panic(errors.Join(ErrCreateFakeProxy, err).Error())
	}

	proxy, err := proxy.NewProxy(config, nil, &FakeUpstreamService{})
	if err != nil {
		panic(errors.Join(ErrCreateFakeProxy, err).Error())
	}

	// step: create an fake upstream endpoint
	service := httptest.NewServer(proxy.Router)
	config.RedirectionURL = service.URL

	// step: we need to update the client config
	if proxy.Provider, proxy.IdpClient, err = proxy.NewOpenIDProvider(); err != nil {
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

func newFakeKeycloakConfig() *config.Config {
	return &config.Config{
		ClientID:                    FakeClientID,
		ClientSecret:                FakeSecret,
		CookieAccessName:            constant.AccessCookie,
		CookieRefreshName:           constant.RefreshCookie,
		CookieIDTokenName:           constant.IDTokenCookie,
		DisableAllLogging:           true,
		DiscoveryURL:                randomLocalHost,
		EnableAuthorizationCookies:  true,
		EnableAuthorizationHeader:   true,
		EnableLogging:               false,
		EnableLoginHandler:          true,
		EnableTokenHeader:           true,
		EnableCompression:           false,
		EnableMetrics:               false,
		Listen:                      randomLocalHost,
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
		Resources: []*authorization.Resource{
			{
				URL:     FakeAdminAllURL,
				Methods: []string{"GET"},
				Roles:   []string{FakeAdminRole},
			},
			{
				URL:     FakeTestRoleURL,
				Methods: []string{"GET"},
				Roles:   []string{FakeTestRole},
			},
			{
				URL:     FakeTestAdminRolesURL,
				Methods: []string{"GET"},
				Roles:   []string{FakeAdminRole, FakeTestRole},
			},
			{
				URL:     FakeAuthAllURL,
				Methods: utils.AllHTTPMethods,
				Roles:   []string{},
			},
			{
				URL:         FakeTestWhitelistedURL,
				WhiteListed: true,
				Methods:     utils.AllHTTPMethods,
				Roles:       []string{},
			},
		},
	}
}

//nolint:cyclop
func makeTestCodeFlowLogin(location string, xforwarded bool) (*http.Response, []*http.Cookie, error) {
	flowCookies := make([]*http.Cookie, 0)

	uri, err := url.Parse(location)

	if err != nil {
		return nil, nil, err
	}
	// step: get the redirect
	var resp *http.Response
	for count := 0; count < 4; count++ {
		req, err := http.NewRequest(http.MethodGet, location, nil)

		for _, cookie := range flowCookies {
			req.AddCookie(cookie)
		}

		if xforwarded {
			req.Header.Add("X-Forwarded-Host", uri.Host)
			req.Header.Add("X-Forwarded-Proto", uri.Scheme)
		}

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
