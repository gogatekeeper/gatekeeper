package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-jose/go-jose/v4/jwt"
	. "github.com/onsi/ginkgo/v2" //nolint:revive //we want to use it for ginkgo
	. "github.com/onsi/gomega"    //nolint:revive //we want to use it for gomega
	"github.com/pquerna/otp/totp"
	"golang.org/x/oauth2/clientcredentials"

	resty "github.com/go-resty/resty/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	keycloakcore "github.com/gogatekeeper/gatekeeper/pkg/keycloak/proxy/core"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/testsuite"
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
	idpURI                  = "http://localhost:8081"
	localURI                = "http://localhost:"
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
	otpSecret             = "NE4VKZJYKVDDSYTIK5CVOOLVOFDFE2DC"
	postLoginRedirectPath = "/post/login/path"
	pkceCookieName        = "TESTPKCECOOKIE"
)

var idpRealmURI = fmt.Sprintf("%s/realms/%s", idpURI, testRealm)

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

var _ = Describe("NoRedirects Simple login/logout", func() {
	var portNum string
	var proxyAddress string

	BeforeEach(func() {
		var err error
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum

		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=true",
			"--enable-default-deny=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--enable-encrypted-token=false",
			"--enable-pkce=false",
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

				respToken, err := conf.Token(ctx)
				Expect(err).NotTo(HaveOccurred())

				request := resty.New().SetRedirectPolicy(
					resty.NoRedirectPolicy()).R().SetAuthToken(respToken.AccessToken)
				resp, err := request.Get(proxyAddress)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				request = resty.New().R().SetAuthToken(respToken.AccessToken)
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

	BeforeEach(func() {
		var err error
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum

		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--upstream-url=" + server.URL,
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
				resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK, testUser, testPass)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body := resp.Body()
				Expect(strings.Contains(string(body), postLoginRedirectPath)).To(BeTrue())
				jarURI, err := url.Parse(proxyAddress)
				Expect(err).NotTo(HaveOccurred())
				cookiesLogin := rClient.GetClient().Jar.Cookies(jarURI)

				tok := testsuite.NewTestToken("example")
				tok.SetExpiration(time.Now().Add(-5 * time.Minute))
				unsignedToken, err := tok.GetUnsignedToken()
				Expect(err).NotTo(HaveOccurred())

				badlySignedToken := unsignedToken + testsuite.FakeSignature
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

	BeforeEach(func() {
		var err error
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum
		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + pkceTestClient,
			"--client-secret=" + pkceTestClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
			"--enable-pkce=true",
			"--cookie-pkce-name=" + pkceCookieName,
			"--enable-encrypted-token=false",
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

	BeforeEach(func() {
		var err error
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddressFirst = "http://127.0.0.1:" + portNum

		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--upstream-url=" + server.URL,
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
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)

		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddressSec = localURI + portNum
		osArgs = []string{os.Args[0]}
		proxyArgs = []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + pkceTestClient,
			"--client-secret=" + pkceTestClientSecret,
			"--upstream-url=" + server.URL,
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
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Login user with one browser client on two clients/app and logout on one of them", func() {
		It("should logout on both successfully", func(_ context.Context) {
			var err error
			rClient := resty.New()
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

	BeforeEach(func() {
		var err error
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum

		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + loaTestClient,
			"--client-secret=" + loaTestClientSecret,
			"--upstream-url=" + server.URL,
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
