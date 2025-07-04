package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-jose/go-jose/v4/jwt"
	resty "github.com/go-resty/resty/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	keycloakcore "github.com/gogatekeeper/gatekeeper/pkg/keycloak/proxy/core"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	testsuite_test "github.com/gogatekeeper/gatekeeper/pkg/testsuite"
	. "github.com/onsi/ginkgo/v2" //nolint:revive //we want to use it for ginkgo
	. "github.com/onsi/gomega"    //nolint:revive //we want to use it for gomega
	"github.com/pquerna/otp/totp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/sync/errgroup"
)

const (
	testRealm  = "test"
	testClient = "test-client"
	//nolint:gosec
	testClientSecret = "6447d0c0-d510-42a7-b654-6e3a16b2d7e2"
	pkceTestClient   = "test-client-pkce"
	//nolint:gosec
	pkceTestClientSecret = "F2GqU40xwX0P2LrTvHUHqwNoSk4U4n5R"
	umaTestClient        = "test-client-uma"
	//nolint:gosec
	umaTestClientSecret = "A5vokiGdI3H2r4aXFrANbKvn4R7cbf6P"
	loaTestClient       = "test-loa"
	//nolint:gosec
	loaTestClientSecret     = "4z9PoOooXNFmSCPZx0xHXaUxX4eYGFO0"
	timeout                 = time.Second * 300
	tlsTimeout              = 10 * time.Second
	idpURI                  = "https://localhost:8443"
	localURI                = "https://localhost:"
	httpLocalURI            = "http://localhost:"
	loginURI                = "/oauth" + constant.LoginURL
	logoutURI               = "/oauth" + constant.LogoutURL
	registerURI             = "/oauth" + constant.RegistrationURL
	allInterfaces           = "0.0.0.0:"
	anyURI                  = "/any"
	testUser                = "myuser"
	testPass                = "baba1234"
	testRegisterUser        = "registerUser"
	testRegisterPass        = "registerPass"
	testLoAUser             = "myloa"
	testLoAPass             = "baba5678"
	testPath                = "/test"
	umaAllowedPath          = "/pets"
	umaForbiddenPath        = "/pets/1"
	umaNonExistentPath      = "/cat"
	umaMethodAllowedPath    = "/horse"
	umaFwdMethodAllowedPath = "/turtle"
	loaPath                 = "/level"
	loaStepUpPath           = "/level2"
	loaDefaultLevel         = "level1"
	loaStepUpLevel          = "level2"

	//nolint:gosec
	otpSecret = "NE4VKZJYKVDDSYTIK5CVOOLVOFDFE2DC"
	redisUser = "default"
	//nolint:gosec
	redisPass = "FYIueRjWqQ"
	//nolint:gosec
	redisClusterPass        = "2aD6FgewLV"
	redisMasterPort         = "6380"
	redisClusterMaster1Port = "7000"
	redisClusterMaster2Port = "7001"
	redisClusterMaster3Port = "7002"
	postLoginRedirectPath   = "/post/login/path"
	pkceCookieName          = "TESTPKCECOOKIE"
	umaCookieName           = "TESTUMACOOKIE"
	idpRealmURI             = idpURI + "/realms/" + testRealm
	//nolint:gosec
	fakePrivateKey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHiHlMGv5dYD1sz60W5AljpbWFbMK11Of/vIpSohwgkdoAoGCCqGSM49
AwEHoUQDQgAEdEq2/CakOBb++B5i/G4+W6sVgz7mKoeDhgq+H0S5gviI56ws5k/M
YPYdwLooCrNBBg9NsW+EcHHDrYmQoMKudw==
-----END EC PRIVATE KEY-----
`

	// we are using dual purpose cert, means we can use it as server side cert and also for client side auth.
	fakeCert = `
-----BEGIN CERTIFICATE-----
MIICkjCCAjigAwIBAgIUE2cox1P7KJoMeyUl6vG65gm/zR0wCgYIKoZIzj0EAwIw
eDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xHzAdBgNVBAoTFkludGVybmV0IFdpZGdldHMsIEluYy4xDDAK
BgNVBAsTA1dXVzENMAsGA1UEAxMEdGVzdDAeFw0yNTA3MDMyMTA4MDBaFw0zNTA3
MDEyMTA4MDBaMFUxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIEwVUZXhhczEPMA0GA1UE
BxMGRGFsbGFzMRcwFQYDVQQKEw5NeSBDZXJ0aWZpY2F0ZTEMMAoGA1UECxMDV1dX
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdEq2/CakOBb++B5i/G4+W6sVgz7m
KoeDhgq+H0S5gviI56ws5k/MYPYdwLooCrNBBg9NsW+EcHHDrYmQoMKud6OBwjCB
vzAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFNRjGKNJPJeFgaGKA2ByZvJfrsA7MB8G
A1UdIwQYMBaAFCJPenCGrRUgGdz1lxbpEpafve3XMEAGA1UdEQQ5MDeCCWxvY2Fs
aG9zdIcEfwAAAYYRaHR0cHM6Ly9sb2NhbGhvc3SGEWh0dHBzOi8vMTI3LjAuMC4x
MAoGCCqGSM49BAMCA0gAMEUCICcv3wTbpuBGY5OeFM85rmskeBAehxbF5OU2SGhO
NyMvAiEA8ZqATZ3Z8hyiUYPhGDNbDAlFGdSnzW7FwC7cWSJL1A8=
-----END CERTIFICATE-----
`

	fakeCA = `
-----BEGIN CERTIFICATE-----
MIICMzCCAdqgAwIBAgIUSwrxz3yTG2X2vz2rsUBbP/chsnYwCgYIKoZIzj0EAwIw
eDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xHzAdBgNVBAoTFkludGVybmV0IFdpZGdldHMsIEluYy4xDDAK
BgNVBAsTA1dXVzENMAsGA1UEAxMEdGVzdDAeFw0yNTA1MTEyMDEzMDBaFw0zNTA1
MDkyMDEzMDBaMHgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYw
FAYDVQQHEw1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKExZJbnRlcm5ldCBXaWRnZXRz
LCBJbmMuMQwwCgYDVQQLEwNXV1cxDTALBgNVBAMTBHRlc3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASEoZEf9zyroblM3zEa6uNB1QCgZ5QNE3Xhr47xkkXS91TE
h03dbIctEYu8K0tbC9YRFxjeLI2JEpSZiNTBLQ8to0IwQDAOBgNVHQ8BAf8EBAMC
AQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUIk96cIatFSAZ3PWXFukSlp+9
7dcwCgYIKoZIzj0EAwIDRwAwRAIgVO5FhzGJWEG+vaqEGHvVPFPKRx2pWyIMYdJl
JaPa7l4CIHss0X1752ReND8FY/NI11GkPVWZaE1HPuJ10SbOog+3
-----END CERTIFICATE-----
`

	//nolint:gosec
	fakeCAKey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKt826IYxvbYqE6h/d9CBEVHs4nmFK0KX8ZH+q4OWcZpoAoGCCqGSM49
AwEHoUQDQgAEhKGRH/c8q6G5TN8xGurjQdUAoGeUDRN14a+O8ZJF0vdUxIdN3WyH
LRGLvCtLWwvWERcY3iyNiRKUmYjUwS0PLQ==
-----END EC PRIVATE KEY-----
`
)

func generateRandomPort() (string, error) {
	var minPort int64 = 1024
	var maxPort int64 = 65000
	maxRand := big.NewInt(maxPort - minPort + 1)
	randPort, err := rand.Int(rand.Reader, maxRand)
	if err != nil {
		return "", err
	}
	randP := int(randPort.Int64() + minPort)
	return strconv.Itoa(randP), nil
}

func startAndWait(portNum string, osArgs []string) {
	go func() {
		defer GinkgoRecover()

		app := proxy.NewOauthProxyApp(keycloakcore.Provider)
		Expect(app.Run(osArgs)).To(Succeed())
	}()

	Eventually(func(_ Gomega) error {
		conn, err := net.Dial("tcp", ":"+portNum)
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}, timeout, 15*time.Second).Should(Succeed())
}

func waitForPort(portNum string) {
	Eventually(func(_ Gomega) error {
		conn, err := net.Dial("tcp", ":"+portNum)
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}, timeout, 15*time.Second).Should(Succeed())
}

func codeFlowLoginSaveStateCookie(
	client *resty.Client,
	reqAddress string,
	expStatusCode int,
	userName string,
	userPass string,
) *resty.Response {
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(5))
	resp, err := client.R().Get(reqAddress)
	Expect(err).NotTo(HaveOccurred())
	Expect(resp.StatusCode()).To(Equal(http.StatusOK))

	// all this stuff with cookies is here to simulate situation in this issue
	// https://github.com/gogatekeeper/gatekeeper/issues/575 - means saving
	// state cookie for later use in test
	jarURI, err := url.Parse(reqAddress)
	Expect(err).NotTo(HaveOccurred())
	cookiesLogin := client.GetClient().Jar.Cookies(jarURI)

	var requestStateCookie http.Cookie
	for _, cook := range cookiesLogin {
		if cook.Name == constant.RequestStateCookie {
			requestStateCookie = *cook
		}
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Body()))
	Expect(err).NotTo(HaveOccurred())

	selection := doc.Find("#kc-form-login")
	Expect(selection).ToNot(BeNil())

	selection.Each(func(_ int, s *goquery.Selection) {
		action, exists := s.Attr("action")
		Expect(exists).To(BeTrue())

		client.FormData.Add("username", userName)
		client.FormData.Add("password", userPass)
		resp, err = client.R().Post(action)

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(expStatusCode))
	})

	cookiesLogin = client.GetClient().Jar.Cookies(jarURI)
	cookiesLogin = append(cookiesLogin, &requestStateCookie)
	client.GetClient().Jar.SetCookies(jarURI, cookiesLogin)

	return resp
}

func codeFlowLogin(
	client *resty.Client,
	reqAddress string,
	expStatusCode int,
	userName string,
	userPass string,
) *resty.Response {
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(5))
	resp, err := client.R().Get(reqAddress)
	Expect(err).NotTo(HaveOccurred())
	Expect(resp.StatusCode()).To(Equal(http.StatusOK))

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Body()))
	Expect(err).NotTo(HaveOccurred())

	selection := doc.Find("#kc-form-login")
	Expect(selection).ToNot(BeNil())

	selection.Each(func(_ int, s *goquery.Selection) {
		action, exists := s.Attr("action")
		Expect(exists).To(BeTrue())

		client.FormData.Add("username", userName)
		client.FormData.Add("password", userPass)
		resp, err = client.R().Post(action)

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(expStatusCode))
	})

	return resp
}

func userPasswordLogin(
	client *resty.Client,
	reqAddress string,
	expStatusCode int,
	userName string,
	userPass string,
) *resty.Response {
	client.SetRedirectPolicy(resty.NoRedirectPolicy())
	client.FormData.Add("username", userName)
	client.FormData.Add("password", userPass)
	resp, err := client.R().Post(reqAddress + loginURI)
	Expect(err).NotTo(HaveOccurred())
	Expect(resp.StatusCode()).To(Equal(expStatusCode))

	return resp
}

func registerLogin(
	client *resty.Client,
	reqAddress string,
	expStatusCode int,
	userName string,
	userPass string,
) *resty.Response {
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(5))
	resp, err := client.R().Get(reqAddress)
	Expect(err).NotTo(HaveOccurred())
	Expect(resp.StatusCode()).To(Equal(http.StatusOK))

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Body()))
	Expect(err).NotTo(HaveOccurred())

	selection := doc.Find("#kc-register-form")
	Expect(selection).ToNot(BeNil())

	selection.Each(func(_ int, s *goquery.Selection) {
		action, exists := s.Attr("action")
		Expect(exists).To(BeTrue())

		client.FormData.Add("username", userName)
		client.FormData.Add("password", userPass)
		client.FormData.Add("password-confirm", userPass)
		client.FormData.Add("email", userName+"@"+userName+".com")
		client.FormData.Add("firstName", userName)
		client.FormData.Add("lastName", userName)
		resp, err = client.R().Post(action)

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(expStatusCode))
	})

	return resp
}

func startAndWaitTestUpstream(errGroup *errgroup.Group) (*http.Server, string) {
	//nolint:gosec
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	Expect(err).NotTo(HaveOccurred())

	tlsCert, err := tls.LoadX509KeyPair(tlsCertificate, tlsPrivateKey)
	Expect(err).NotTo(HaveOccurred())

	tlsConfig := &tls.Config{
		Certificates:             []tls.Certificate{tlsCert},
		PreferServerCipherSuites: true,
		NextProtos:               []string{"h2", "http/1.1"},
		MinVersion:               tls.VersionTLS13,
	}

	listener = tls.NewListener(listener, tlsConfig)
	//nolint:gosec
	server := &http.Server{
		Addr:      listener.Addr().String(),
		Handler:   &testsuite_test.FakeUpstreamService{},
		TLSConfig: tlsConfig,
	}

	errGroup.Go(func() error {
		err = server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})

	netParts := strings.Split(listener.Addr().String(), ":")
	port := netParts[len(netParts)-1]
	Eventually(func(_ Gomega) error {
		ctx, cancel := context.WithTimeout(context.Background(), tlsTimeout)
		dialer := tls.Dialer{
			Config: &tls.Config{
				ServerName: "localhost",
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS13,
			},
		}

		conn, err := dialer.DialContext(ctx, "tcp", ":"+port)
		cancel()
		Expect(err).NotTo(HaveOccurred())

		conn.Close()
		return nil
	}, timeout, tlsTimeout).Should(Succeed())

	return server, port
}

var _ = Describe("NoRedirects Simple login/logout", func() {
	var portNum string
	var proxyAddress string
	errGroup, _ := errgroup.WithContext(context.Background())
	var server *http.Server

	AfterEach(func() {
		if server != nil {
			err := server.Shutdown(context.Background())
			Expect(err).NotTo(HaveOccurred())
		}
		if errGroup != nil {
			err := errGroup.Wait()
			Expect(err).NotTo(HaveOccurred())
		}
	})

	BeforeEach(func() {
		var err error
		var upstreamSvcPort string

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup)
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum

		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--skip-openid-provider-tls-verify=true",
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--upstream-url=" + localURI + upstreamSvcPort,
			"--no-redirects=true",
			"--enable-default-deny=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--enable-encrypted-token=false",
			"--enable-pkce=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Performing standard login", func() {
		It("should login with service account and logout successfully",
			Label("api_flow"),
			Label("basic_case"),
			func(ctx context.Context) {
				conf := &clientcredentials.Config{
					ClientID:     testClient,
					ClientSecret: testClientSecret,
					Scopes:       []string{"email", "openid"},
					TokenURL:     idpRealmURI + constant.IdpTokenURI,
				}

				rClient := resty.New()
				hClient := rClient.SetTLSClientConfig(
					&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13}).GetClient()
				oidcLibCtx := context.WithValue(ctx, oauth2.HTTPClient, hClient)

				respToken, err := conf.Token(oidcLibCtx)
				Expect(err).NotTo(HaveOccurred())

				rClient = resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})

				request := rClient.SetRedirectPolicy(
					resty.NoRedirectPolicy()).R().SetAuthToken(respToken.AccessToken)
				resp, err := request.Get(proxyAddress)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				rClient = resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})

				request = rClient.R().SetAuthToken(respToken.AccessToken)
				resp, err = request.Get(proxyAddress + logoutURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
			},
		)
	})
})

var _ = Describe("Code Flow login/logout", func() {
	var portNum string
	var proxyAddress string
	errGroup, _ := errgroup.WithContext(context.Background())
	var server *http.Server

	AfterEach(func() {
		if server != nil {
			err := server.Shutdown(context.Background())
			Expect(err).NotTo(HaveOccurred())
		}
		if errGroup != nil {
			err := errGroup.Wait()
			Expect(err).NotTo(HaveOccurred())
		}
	})

	BeforeEach(func() {
		var err error
		var upstreamSvcPort string

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup)
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum

		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--openid-provider-ca=" + tlsCaCertificate,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--upstream-url=" + localURI + upstreamSvcPort,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--enable-idp-session-check=false",
			"--enable-default-deny=false",
			"--resources=uri=/*|roles=uma_authorization,offline_access",
			"--openid-provider-retry-count=30",
			"--enable-refresh-tokens=true",
			"--encryption-key=sdkljfalisujeoir",
			"--secure-cookie=false",
			"--post-login-redirect-path=" + postLoginRedirectPath,
			"--enable-register-handler=true",
			"--enable-encrypted-token=false",
			"--enable-pkce=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Performing standard login", func() {
		It("should login with user/password and logout successfully",
			Label("code_flow"),
			Label("basic_case"),
			func(_ context.Context) {
				var err error
				rClient := resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
				resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK, testUser, testPass)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body := resp.Body()
				Expect(strings.Contains(string(body), postLoginRedirectPath)).To(BeTrue())
				jarURI, err := url.Parse(proxyAddress)
				Expect(err).NotTo(HaveOccurred())
				cookiesLogin := rClient.GetClient().Jar.Cookies(jarURI)

				var accessCookieLogin string
				for _, cook := range cookiesLogin {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}
				}

				By("wait for access token expiration")
				time.Sleep(32 * time.Second)
				resp, err = rClient.R().Get(proxyAddress + anyURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body = resp.Body()
				Expect(strings.Contains(string(body), anyURI)).To(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(err).NotTo(HaveOccurred())
				cookiesAfterRefresh := rClient.GetClient().Jar.Cookies(jarURI)

				var accessCookieAfterRefresh string
				for _, cook := range cookiesAfterRefresh {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}
				}

				By("check if access token cookie has changed")
				Expect(accessCookieLogin).NotTo(Equal(accessCookieAfterRefresh))

				By("make another request with new access token")
				resp, err = rClient.R().Get(proxyAddress + anyURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body = resp.Body()
				Expect(strings.Contains(string(body), anyURI)).To(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				By("log out")
				resp, err = rClient.R().Get(proxyAddress + logoutURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
				resp, _ = rClient.R().Get(proxyAddress)
				Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
			},
		)
	})

	When("Using forged expired access token with valid refresh token", func() {
		It("should be forbidden",
			Label("code_flow"),
			Label("forged_access_token"),
			Label("attack"),
			func(_ context.Context) {
				var err error
				rClient := resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
				resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK, testUser, testPass)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body := resp.Body()
				Expect(strings.Contains(string(body), postLoginRedirectPath)).To(BeTrue())
				jarURI, err := url.Parse(proxyAddress)
				Expect(err).NotTo(HaveOccurred())
				cookiesLogin := rClient.GetClient().Jar.Cookies(jarURI)

				tok := testsuite_test.NewTestToken("example")
				tok.SetExpiration(time.Now().Add(-5 * time.Minute))
				unsignedToken, err := tok.GetUnsignedToken()
				Expect(err).NotTo(HaveOccurred())

				badlySignedToken := unsignedToken + testsuite_test.FakeSignature
				for _, cook := range cookiesLogin {
					if cook.Name == constant.AccessCookie {
						cook.Value = badlySignedToken
					}
				}

				rClient.GetClient().Jar.SetCookies(jarURI, cookiesLogin)

				By("make another request with forged access token")
				resp, err = rClient.R().Get(proxyAddress + anyURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(strings.Contains(string(body), anyURI)).To(BeFalse())
				Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))

				By("log out")
				resp, err = rClient.R().Get(proxyAddress + logoutURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
			},
		)
	})

	When("Performing registration", func() {
		It("should register/login and logout successfully",
			Label("code_flow"),
			Label("register_case"),
			func(_ context.Context) {
				var err error
				rClient := resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
				reqAddress := proxyAddress + registerURI
				resp := registerLogin(rClient, reqAddress, http.StatusOK, testRegisterUser, testRegisterPass)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body := resp.Body()
				Expect(strings.Contains(string(body), postLoginRedirectPath)).To(BeTrue())
				jarURI, err := url.Parse(proxyAddress)
				Expect(err).NotTo(HaveOccurred())
				cookiesLogin := rClient.GetClient().Jar.Cookies(jarURI)

				var accessCookieLogin string
				for _, cook := range cookiesLogin {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}
				}

				By("wait for access token expiration")
				time.Sleep(32 * time.Second)
				resp, err = rClient.R().Get(proxyAddress + anyURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body = resp.Body()
				Expect(strings.Contains(string(body), anyURI)).To(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(err).NotTo(HaveOccurred())
				cookiesAfterRefresh := rClient.GetClient().Jar.Cookies(jarURI)

				var accessCookieAfterRefresh string
				for _, cook := range cookiesAfterRefresh {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}
				}

				By("check if access token cookie has changed")
				Expect(accessCookieLogin).NotTo(Equal(accessCookieAfterRefresh))

				By("make another request with new access token")
				resp, err = rClient.R().Get(proxyAddress + anyURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body = resp.Body()
				Expect(strings.Contains(string(body), anyURI)).To(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				By("log out")
				resp, err = rClient.R().Get(proxyAddress + logoutURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
				resp, _ = rClient.R().Get(proxyAddress)
				Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
			},
		)
	})
})

var _ = Describe("Code Flow PKCE login/logout", func() {
	var portNum string
	var proxyAddress string
	errGroup, _ := errgroup.WithContext(context.Background())
	var server *http.Server

	AfterEach(func() {
		if server != nil {
			err := server.Shutdown(context.Background())
			Expect(err).NotTo(HaveOccurred())
		}
		if errGroup != nil {
			err := errGroup.Wait()
			Expect(err).NotTo(HaveOccurred())
		}
	})

	BeforeEach(func() {
		var err error
		var upstreamSvcPort string

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup)
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum
		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--openid-provider-ca=" + tlsCaCertificate,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + pkceTestClient,
			"--client-secret=" + pkceTestClientSecret,
			"--upstream-url=" + localURI + upstreamSvcPort,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
			"--enable-pkce=true",
			"--cookie-pkce-name=" + pkceCookieName,
			"--enable-encrypted-token=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--tls-ca-certificate=" + tlsCaCertificate,
			"--upstream-ca=" + tlsCaCertificate,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Peforming standard login", func() {
		It("should login with user/password and logout successfully",
			Label("code_flow"),
			Label("pkce"),
			func(_ context.Context) {
				var err error
				rClient := resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})

				resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK, testUser, testPass)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

				body := resp.Body()
				Expect(strings.Contains(string(body), pkceCookieName)).To(BeTrue())

				resp, err = rClient.R().Get(proxyAddress + logoutURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
				resp, _ = rClient.R().Get(proxyAddress)
				Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
			},
		)
	})
})

var _ = Describe("Code Flow PKCE login/logout with REDIS", func() {
	var portNum string
	var proxyAddress string
	errGroup, _ := errgroup.WithContext(context.Background())
	var server *http.Server

	AfterEach(func() {
		if server != nil {
			err := server.Shutdown(context.Background())
			Expect(err).NotTo(HaveOccurred())
		}
		if errGroup != nil {
			err := errGroup.Wait()
			Expect(err).NotTo(HaveOccurred())
		}
	})

	BeforeEach(func() {
		var err error
		var upstreamSvcPort string

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup)
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum
		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--openid-provider-ca=" + tlsCaCertificate,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + pkceTestClient,
			"--client-secret=" + pkceTestClientSecret,
			"--upstream-url=" + localURI + upstreamSvcPort,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
			"--enable-pkce=true",
			"--cookie-pkce-name=" + pkceCookieName,
			"--enable-encrypted-token=false",
			"--enable-refresh-tokens=true",
			"--encryption-key=sdkljfalisujeoir",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--tls-ca-certificate=" + tlsCaCertificate,
			"--upstream-ca=" + tlsCaCertificate,
			"--store-url=rediss://" + redisUser + ":" + redisPass + "@localhost:" + redisMasterPort + "/0",
			"--tls-store-ca-certificate=" + tlsCaCertificate,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
		waitForPort(redisMasterPort)
	})

	When("Peforming standard login", func() {
		It("should login with user/password and logout successfully",
			Label("code_flow", "pkce", "redis"),
			func(_ context.Context) {
				var err error
				rClient := resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})

				resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK, testUser, testPass)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

				body := resp.Body()
				Expect(strings.Contains(string(body), pkceCookieName)).To(BeTrue())

				resp, err = rClient.R().Get(proxyAddress + logoutURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
				resp, _ = rClient.R().Get(proxyAddress)
				Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
			},
		)
	})
})

var _ = Describe("Code Flow PKCE login/logout with REDIS CLUSTER", func() {
	var portNum string
	var proxyAddress string
	errGroup, _ := errgroup.WithContext(context.Background())
	var server *http.Server

	AfterEach(func() {
		if server != nil {
			err := server.Shutdown(context.Background())
			Expect(err).NotTo(HaveOccurred())
		}
		if errGroup != nil {
			err := errGroup.Wait()
			Expect(err).NotTo(HaveOccurred())
		}
	})

	BeforeEach(func() {
		var err error
		var upstreamSvcPort string

		redisClusterURL := "rediss://" + redisUser + ":" + redisClusterPass + "@127.0.0.1:" + redisClusterMaster1Port
		redisClusterURL += "?dial_timeout=3&read_timeout=6s&addr=127.0.0.1:" + redisClusterMaster2Port
		redisClusterURL += "&addr=127.0.0.1:" + redisClusterMaster3Port

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup)
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum
		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--openid-provider-ca=" + tlsCaCertificate,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + pkceTestClient,
			"--client-secret=" + pkceTestClientSecret,
			"--upstream-url=" + localURI + upstreamSvcPort,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
			"--enable-pkce=true",
			"--cookie-pkce-name=" + pkceCookieName,
			"--enable-encrypted-token=false",
			"--enable-refresh-tokens=true",
			"--encryption-key=sdkljfalisujeoir",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--tls-ca-certificate=" + tlsCaCertificate,
			"--upstream-ca=" + tlsCaCertificate,
			"--store-url=" + redisClusterURL,
			"--enable-store-ha=true",
			"--tls-store-ca-certificate=" + tlsCaCertificate,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
		waitForPort(redisClusterMaster1Port)
		waitForPort(redisClusterMaster2Port)
		waitForPort(redisClusterMaster3Port)
	})

	When("Peforming standard login", func() {
		It("should login with user/password and logout successfully",
			Label("code_flow", "pkce", "redis_cluster"),
			func(_ context.Context) {
				var err error
				rClient := resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})

				resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK, testUser, testPass)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

				body := resp.Body()
				Expect(strings.Contains(string(body), pkceCookieName)).To(BeTrue())

				resp, err = rClient.R().Get(proxyAddress + logoutURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
				resp, _ = rClient.R().Get(proxyAddress)
				Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
			},
		)
	})
})

var _ = Describe("Code Flow login/logout with session check", func() {
	var portNum string
	var proxyAddressFirst string
	var proxyAddressSec string
	errGroup, _ := errgroup.WithContext(context.Background())
	var server *http.Server

	AfterEach(func() {
		if server != nil {
			err := server.Shutdown(context.Background())
			Expect(err).NotTo(HaveOccurred())
		}
		if errGroup != nil {
			err := errGroup.Wait()
			Expect(err).NotTo(HaveOccurred())
		}
	})

	BeforeEach(func() {
		var err error
		var upstreamSvcPort string

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup)
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddressFirst = "https://127.0.0.1:" + portNum

		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--openid-provider-ca=" + tlsCaCertificate,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--upstream-url=" + localURI + upstreamSvcPort,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
			"--enable-idp-session-check=true",
			"--enable-logout-redirect=true",
			"--enable-id-token-cookie=true",
			"--post-logout-redirect-uri=http://google.com",
			"--enable-encrypted-token=false",
			"--enable-pkce=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)

		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddressSec = localURI + portNum
		osArgs = []string{os.Args[0]}
		proxyArgs = []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--openid-provider-ca=" + tlsCaCertificate,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + pkceTestClient,
			"--client-secret=" + pkceTestClientSecret,
			"--upstream-url=" + localURI + upstreamSvcPort,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
			"--enable-pkce=true",
			"--cookie-pkce-name=" + pkceCookieName,
			"--enable-idp-session-check=true",
			"--enable-logout-redirect=true",
			"--enable-id-token-cookie=true",
			"--post-logout-redirect-uri=http://google.com",
			"--enable-encrypted-token=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Login user with one browser client on two clients/app and logout on one of them", func() {
		It("should logout on both successfully", func(_ context.Context) {
			var err error
			rClient := resty.New()
			rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
			resp := codeFlowLogin(rClient, proxyAddressFirst, http.StatusOK, testUser, testPass)
			Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
			resp = codeFlowLogin(rClient, proxyAddressSec, http.StatusOK, testUser, testPass)
			Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

			resp, err = rClient.R().Get(proxyAddressFirst + testPath)
			Expect(err).NotTo(HaveOccurred())
			body := resp.Body()
			Expect(strings.Contains(string(body), testPath)).To(BeTrue())

			resp, err = rClient.R().Get(proxyAddressSec + testPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))
			body = resp.Body()
			Expect(strings.Contains(string(body), testPath)).To(BeTrue())

			By("Logout user on first client")
			resp, err = rClient.R().Get(proxyAddressFirst + logoutURI)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			By("Verify logged out on second client")
			rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
			resp, _ = rClient.R().Get(proxyAddressSec)
			Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))

			By("Verify logged out on first client")
			rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
			resp, _ = rClient.R().Get(proxyAddressFirst)
			Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
		})
	})
})

var _ = Describe("Level Of Authentication Code Flow login/logout", func() {
	var portNum string
	var proxyAddress string
	errGroup, _ := errgroup.WithContext(context.Background())
	var server *http.Server

	AfterEach(func() {
		if server != nil {
			err := server.Shutdown(context.Background())
			Expect(err).NotTo(HaveOccurred())
		}
		if errGroup != nil {
			err := errGroup.Wait()
			Expect(err).NotTo(HaveOccurred())
		}
	})

	BeforeEach(func() {
		var err error
		var upstreamSvcPort string

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup)
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum

		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--openid-provider-ca=" + tlsCaCertificate,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + loaTestClient,
			"--client-secret=" + loaTestClientSecret,
			"--upstream-url=" + localURI + upstreamSvcPort,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--enable-idp-session-check=false",
			"--enable-default-deny=true",
			"--enable-loa=true",
			"--verbose=true",
			"--resources=uri=" + loaPath + "|acr=level1,level2",
			"--resources=uri=" + loaStepUpPath + "|acr=level2",
			"--openid-provider-retry-count=30",
			"--enable-refresh-tokens=true",
			"--encryption-key=sdkljfalisujeoir",
			"--secure-cookie=false",
			"--post-login-redirect-path=" + postLoginRedirectPath,
			"--enable-encrypted-token=false",
			"--enable-pkce=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Performing standard loa login", func() {
		It("should login with loa level1=user/password and logout successfully",
			Label("code_flow"),
			Label("basic_case"),
			Label("loa"),
			func(_ context.Context) {
				var err error
				rClient := resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
				resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK, testLoAUser, testLoAPass)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body := resp.Body()
				Expect(strings.Contains(string(body), postLoginRedirectPath)).To(BeTrue())
				jarURI, err := url.Parse(proxyAddress)
				Expect(err).NotTo(HaveOccurred())
				cookiesLogin := rClient.GetClient().Jar.Cookies(jarURI)

				var accessCookieLogin string
				for _, cook := range cookiesLogin {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}
				}

				By("wait for access token expiration")
				time.Sleep(32 * time.Second)
				resp, err = rClient.R().Get(proxyAddress + anyURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body = resp.Body()
				Expect(strings.Contains(string(body), anyURI)).To(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(err).NotTo(HaveOccurred())
				cookiesAfterRefresh := rClient.GetClient().Jar.Cookies(jarURI)

				var accessCookieAfterRefresh string
				for _, cook := range cookiesAfterRefresh {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}
				}

				By("check if access token cookie has changed")
				Expect(accessCookieLogin).NotTo(Equal(accessCookieAfterRefresh))

				By("make another request with new access token")
				resp, err = rClient.R().Get(proxyAddress + anyURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body = resp.Body()
				Expect(strings.Contains(string(body), anyURI)).To(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				By("verify access token contains default acr value")
				token, err := jwt.ParseSigned(accessCookieLogin, constant.SignatureAlgs[:])
				Expect(err).NotTo(HaveOccurred())
				customClaims := models.CustClaims{}

				err = token.UnsafeClaimsWithoutVerification(&customClaims)
				Expect(err).NotTo(HaveOccurred())
				Expect(customClaims.Acr).To(Equal(loaDefaultLevel))

				By("log out")
				resp, err = rClient.R().Get(proxyAddress + logoutURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
				resp, _ = rClient.R().Get(proxyAddress)
				Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
			},
		)
	})

	When("Performing step up loa login", func() {
		It("should login with loa level2=user/password and logout successfully",
			Label("code_flow"),
			Label("basic_case"),
			Label("loa"),
			func(_ context.Context) {
				var err error
				rClient := resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
				resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK, testLoAUser, testLoAPass)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body := resp.Body()
				Expect(strings.Contains(string(body), postLoginRedirectPath)).To(BeTrue())
				jarURI, err := url.Parse(proxyAddress)
				Expect(err).NotTo(HaveOccurred())
				cookiesLogin := rClient.GetClient().Jar.Cookies(jarURI)

				var accessCookieLogin string
				for _, cook := range cookiesLogin {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}
				}

				By("verify access token contains default acr value")
				token, err := jwt.ParseSigned(accessCookieLogin, constant.SignatureAlgs[:])
				Expect(err).NotTo(HaveOccurred())
				customClaims := models.CustClaims{}

				err = token.UnsafeClaimsWithoutVerification(&customClaims)
				Expect(err).NotTo(HaveOccurred())
				Expect(customClaims.Acr).To(Equal(loaDefaultLevel))

				By("make step up request")
				resp, err = rClient.R().Get(proxyAddress + loaStepUpPath)
				Expect(err).NotTo(HaveOccurred())
				body = resp.Body()

				doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
				Expect(err).NotTo(HaveOccurred())

				selection := doc.Find("#kc-otp-login-form")
				Expect(selection).ToNot(BeNil())
				Expect(selection.Nodes).ToNot(BeEmpty())

				selection.Each(func(_ int, s *goquery.Selection) {
					action, exists := s.Attr("action")
					Expect(exists).To(BeTrue())

					otp, errOtp := totp.GenerateCode(otpSecret, time.Now().UTC())
					Expect(errOtp).NotTo(HaveOccurred())
					rClient.FormData.Del("username")
					rClient.FormData.Del("password")
					rClient.FormData.Set("otp", otp)
					rClient.SetRedirectPolicy(resty.FlexibleRedirectPolicy(2))
					rClient.SetBaseURL(proxyAddress)
					resp, err = rClient.R().Post(action)
					loc := resp.Header().Get("Location")

					resp, err = rClient.R().Get(loc)
					Expect(err).NotTo(HaveOccurred())
					Expect(strings.Contains(string(resp.Body()), loaStepUpPath)).To(BeTrue())
					Expect(resp.StatusCode()).To(Equal(http.StatusOK))

					By("verify access token contains raised acr value")
					cookiesLogin := rClient.GetClient().Jar.Cookies(jarURI)

					var accessCookieLogin string
					for _, cook := range cookiesLogin {
						if cook.Name == constant.AccessCookie {
							accessCookieLogin = cook.Value
						}
					}
					token, err = jwt.ParseSigned(accessCookieLogin, constant.SignatureAlgs[:])
					Expect(err).NotTo(HaveOccurred())
					customClaims := models.CustClaims{}

					err = token.UnsafeClaimsWithoutVerification(&customClaims)
					Expect(err).NotTo(HaveOccurred())
					Expect(customClaims.Acr).To(Equal(loaStepUpLevel))
				})

				By("log out")
				resp, err = rClient.R().Get(proxyAddress + logoutURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
				resp, _ = rClient.R().Get(proxyAddress)
				Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
			},
		)
	})
})

var _ = Describe("User/password login/logout", func() {
	var portNum string
	var proxyAddress string
	errGroup, _ := errgroup.WithContext(context.Background())
	var server *http.Server

	AfterEach(func() {
		if server != nil {
			err := server.Shutdown(context.Background())
			Expect(err).NotTo(HaveOccurred())
		}
		if errGroup != nil {
			err := errGroup.Wait()
			Expect(err).NotTo(HaveOccurred())
		}
	})

	BeforeEach(func() {
		var err error
		var upstreamSvcPort string

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup)
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum

		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--openid-provider-ca=" + tlsCaCertificate,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--upstream-url=" + localURI + upstreamSvcPort,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--enable-idp-session-check=false",
			"--enable-default-deny=false",
			"--resources=uri=/*|roles=uma_authorization,offline_access",
			"--openid-provider-retry-count=30",
			"--enable-refresh-tokens=true",
			"--encryption-key=sdkljfalisujeoir",
			"--secure-cookie=false",
			"--post-login-redirect-path=" + postLoginRedirectPath,
			"--enable-login-handler=true",
			"--enable-encrypted-token=false",
			"--enable-pkce=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Performing user/password login", func() {
		It("should login with user/password and logout successfully",
			Label("user_password_flow"),
			Label("basic_case"),
			func(_ context.Context) {
				var err error
				rClient := resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
				resp := userPasswordLogin(rClient, proxyAddress, http.StatusOK, testUser, testPass)
				body := resp.Body()

				jarURI, err := url.Parse(proxyAddress)
				Expect(err).NotTo(HaveOccurred())
				cookiesLogin := rClient.GetClient().Jar.Cookies(jarURI)

				var accessCookieLogin string
				var refreshCookieLogin string
				for _, cook := range cookiesLogin {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}
					if cook.Name == constant.RefreshCookie {
						refreshCookieLogin = cook.Value
					}
				}

				Expect(strings.Contains(string(body), accessCookieLogin)).To(BeTrue())
				Expect(strings.Contains(string(body), refreshCookieLogin)).To(BeTrue())

				By("wait for access token expiration")
				time.Sleep(32 * time.Second)
				resp, err = rClient.R().Get(proxyAddress + anyURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body = resp.Body()
				Expect(strings.Contains(string(body), anyURI)).To(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(err).NotTo(HaveOccurred())
				cookiesAfterRefresh := rClient.GetClient().Jar.Cookies(jarURI)

				var accessCookieAfterRefresh string
				for _, cook := range cookiesAfterRefresh {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}
				}

				By("check if access token cookie has changed")
				Expect(accessCookieLogin).NotTo(Equal(accessCookieAfterRefresh))

				By("make another request with new access token")
				resp, err = rClient.R().Get(proxyAddress + anyURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body = resp.Body()
				Expect(strings.Contains(string(body), anyURI)).To(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				By("log out")
				resp, err = rClient.R().Get(proxyAddress + logoutURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
				resp, _ = rClient.R().Get(proxyAddress)
				Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
			},
		)
	})

	When("Performing code flow login and then user/password login", func() {
		It("should login with user/password and logout successfully",
			Label("user_password_flow"),
			Label("basic_case"),
			func(_ context.Context) {
				var err error
				rClient := resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
				resp := codeFlowLoginSaveStateCookie(rClient, proxyAddress, http.StatusOK, testUser, testPass)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body := resp.Body()
				Expect(strings.Contains(string(body), postLoginRedirectPath)).To(BeTrue())
				jarURI, err := url.Parse(proxyAddress)
				Expect(err).NotTo(HaveOccurred())
				cookiesLogin := rClient.GetClient().Jar.Cookies(jarURI)

				var codeAccessCookieLogin string
				for _, cook := range cookiesLogin {
					if cook.Name == constant.AccessCookie {
						codeAccessCookieLogin = cook.Value
					}
				}

				resp = userPasswordLogin(rClient, proxyAddress, http.StatusOK, testUser, testPass)
				body = resp.Body()

				jarURI, err = url.Parse(proxyAddress)
				Expect(err).NotTo(HaveOccurred())
				cookiesLogin = rClient.GetClient().Jar.Cookies(jarURI)

				var accessCookieLogin string
				var refreshCookieLogin string
				for _, cook := range cookiesLogin {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}
					if cook.Name == constant.RefreshCookie {
						refreshCookieLogin = cook.Value
					}
				}

				Expect(codeAccessCookieLogin).NotTo(Equal(accessCookieLogin))
				Expect(strings.Contains(string(body), accessCookieLogin)).To(BeTrue())
				Expect(strings.Contains(string(body), refreshCookieLogin)).To(BeTrue())

				By("wait for access token expiration")
				time.Sleep(32 * time.Second)
				resp, err = rClient.R().Get(proxyAddress + anyURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body = resp.Body()
				Expect(strings.Contains(string(body), anyURI)).To(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(err).NotTo(HaveOccurred())
				cookiesAfterRefresh := rClient.GetClient().Jar.Cookies(jarURI)

				var accessCookieAfterRefresh string
				for _, cook := range cookiesAfterRefresh {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}
				}

				By("check if access token cookie has changed")
				Expect(accessCookieLogin).NotTo(Equal(accessCookieAfterRefresh))

				By("make another request with new access token")
				resp, err = rClient.R().Get(proxyAddress + anyURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body = resp.Body()
				Expect(strings.Contains(string(body), anyURI)).To(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				By("log out")
				resp, err = rClient.R().Get(proxyAddress + logoutURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
				resp, _ = rClient.R().Get(proxyAddress)
				Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
			},
		)
	})
})
