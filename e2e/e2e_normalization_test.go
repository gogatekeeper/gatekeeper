package e2e_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	resty "github.com/go-resty/resty/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	. "github.com/onsi/ginkgo/v2" //nolint:revive //we want to use it for ginkgo
	. "github.com/onsi/gomega"    //nolint:revive //we want to use it for gomega
	"golang.org/x/sync/errgroup"
)

var _ = Describe("Code Flow login/logout all normalization disabled", func() {
	var (
		portNum      string
		proxyAddress string
		server       *http.Server
		rawServer    *net.Listener
	)

	errGroup, _ := errgroup.WithContext(context.Background())

	AfterEach(func() {
		if server != nil {
			err := server.Shutdown(context.Background())
			Expect(err).NotTo(HaveOccurred())
		}

		if rawServer != nil {
			err := (*rawServer).Close()
			Expect(err).NotTo(HaveOccurred())
		}

		if errGroup != nil {
			err := errGroup.Wait()
			Expect(err).NotTo(HaveOccurred())
		}
	})

	BeforeEach(func() {
		var (
			err             error
			upstreamSvcPort string
		)

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup, false, false, false)

		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())

		proxyAddress = localURI + portNum

		//nolint:goconst
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--tls-openid-provider-ca-certificate=" + tlsCaCertificate,
			"--tls-openid-provider-client-certificate=" + tlsCertificate,
			"--tls-openid-provider-client-private-key=" + tlsPrivateKey,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--upstream-url=" + localURI + upstreamSvcPort,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--enable-idp-session-check=false",
			"--enable-default-deny=false",
			"--resources=uri=" + postLoginRedirectPath + "|roles=uma_authorization,offline_access",
			"--resources=uri=/|roles=uma_authorization,offline_access",
			"--resources=uri=/.%2e/../%2F/api/v1/%61uth/some*|roles=uma_authorization,offline_access",
			"--resources=uri=" + anyURI + "|roles=uma_authorization,offline_access",
			"--resources=uri=/../api/v1/%61uth/some|roles=non-existent",
			"--openid-provider-retry-count=30",
			"--enable-refresh-tokens=true",
			"--encryption-key=" + testKey,
			"--secure-cookie=false",
			"--enable-register-handler=true",
			"--enable-encrypted-token=false",
			"--enable-id-token-claims=true",
			"--enable-id-token-cookie=true",
			"--enable-user-info-claims=true",
			"--add-claims=email_verified",
			"--add-claims=email",
			"--enable-pkce=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
			"--normalize-path=false",
			"--normalize-path-upstream=false",
			"--merge-slashes=false",
			"--merge-slashes-upstream=false",
			"--path-escaped-slashes=true",
			"--path-escaped-slashes-upstream=true",
			"--enable-logging=true",
		}

		osArgs := make([]string, 0, 1+len(proxyArgs))
		osArgs = append(osArgs, os.Args[0])
		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Performing standard login", func() {
		It(
			"should login with user/password and logout successfully",
			Label("code_flow"),
			Label("basic_case"),
			Label("normalization_disabled"),
			func(_ context.Context) {
				var err error

				ctx, cancel := context.WithTimeout(context.Background(), tlsTimeout)
				dialer := tls.Dialer{
					Config: &tls.Config{
						ServerName: "localhost",
						RootCAs:    caPool,
						MinVersion: tls.VersionTLS13,
					},
				}

				conn, err := dialer.DialContext(ctx, "tcp", ":"+portNum)
				Expect(err).NotTo(HaveOccurred())

				loginPath := proxyAddress + postLoginRedirectPath + "?param=val1"
				rClient := resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
				resp := codeFlowLogin(rClient, loginPath, http.StatusOK, testUser, testPass)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body := resp.Body()
				Expect(strings.Contains(string(body), postLoginRedirectPath+"?param=val1")).To(BeTrue())

				jarURI, err := url.Parse(proxyAddress + postLoginRedirectPath)
				Expect(err).NotTo(HaveOccurred())

				cookiesLogin := rClient.GetClient().Jar.Cookies(jarURI)

				var (
					accessCookieLogin string
					idCookieLogin     string
				)

				for _, cook := range cookiesLogin {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}

					if cook.Name == constant.IDTokenCookie {
						idCookieLogin = cook.Value
					}
				}

				to := time.Now().Add(60 * time.Second)
				err = conn.SetDeadline(to)
				Expect(err).NotTo(HaveOccurred())

				tricky := "//"
				rawRequest := "GET " + tricky + " HTTP/1.1\r\n"
				repeatRaw := httpLocalHostHeader
				repeatRaw += "Cookie: " + constant.AccessCookie + "=" + accessCookieLogin + "; "
				repeatRaw += constant.IDTokenCookie + "=" + idCookieLogin
				repeatRaw += httpBodySeparator
				rawRequest += repeatRaw

				_, err = conn.Write([]byte(rawRequest))
				Expect(err).NotTo(HaveOccurred())

				rawResp := make([]byte, 1024)
				_, err = conn.Read(rawResp)

				cancel()
				conn.Close()

				Expect(err).NotTo(HaveOccurred())
				Expect(strings.Contains(string(rawResp), tricky)).To(BeTrue())
				Expect(strings.Contains(string(rawResp), "200")).To(BeTrue())

				ctx, cancel = context.WithTimeout(context.Background(), tlsTimeout)
				conn, err = dialer.DialContext(ctx, "tcp", ":"+portNum)
				Expect(err).NotTo(HaveOccurred())

				tricky = "//really%2e///tricky//"
				rawRequest = "GET " + tricky + " HTTP/1.1\r\n"
				rawRequest += repeatRaw

				_, err = conn.Write([]byte(rawRequest))
				Expect(err).NotTo(HaveOccurred())

				rawResp = make([]byte, 1024)
				_, err = conn.Read(rawResp)

				cancel()
				conn.Close()

				Expect(err).NotTo(HaveOccurred())
				Expect(strings.Contains(string(rawResp), tricky)).To(BeTrue())
				Expect(strings.Contains(string(rawResp), "200")).To(BeTrue())

				tricky = "/../api/v1/%61uth/some"
				resp, err = rClient.R().Get(proxyAddress + tricky)
				Expect(err).NotTo(HaveOccurred())

				body = resp.Body()
				Expect(strings.Contains(string(body), tricky)).NotTo(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))

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

var _ = Describe("Code Flow login/logout all normalization disabled precise encoded output", func() {
	var (
		portNum string
		// proxyAddress string
		server    *http.Server
		rawServer *net.Listener
	)

	errGroup, _ := errgroup.WithContext(context.Background())

	AfterEach(func() {
		if server != nil {
			err := server.Shutdown(context.Background())
			Expect(err).NotTo(HaveOccurred())
		}

		if rawServer != nil {
			err := (*rawServer).Close()
			Expect(err).NotTo(HaveOccurred())
		}

		if errGroup != nil {
			err := errGroup.Wait()
			Expect(err).NotTo(HaveOccurred())
		}
	})

	BeforeEach(func() {
		var (
			err error
			// upstreamSvcPort    string
			rawUpstreamSvcPort string
		)

		rawServer, rawUpstreamSvcPort = startAndWaitTestRawUpstream(errGroup, false)

		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())

		//nolint:goconst
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--tls-openid-provider-ca-certificate=" + tlsCaCertificate,
			"--tls-openid-provider-client-certificate=" + tlsCertificate,
			"--tls-openid-provider-client-private-key=" + tlsPrivateKey,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--upstream-url=" + localURI + rawUpstreamSvcPort,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--enable-idp-session-check=false",
			"--enable-default-deny=false",
			"--resources=uri=" + postLoginRedirectPath + "|roles=uma_authorization,offline_access",
			"--resources=uri=/|roles=uma_authorization,offline_access",
			"--resources=uri=/.%2e/../%2F/api/v1/%61uth/some*|roles=uma_authorization,offline_access",
			"--resources=uri=" + anyURI + "|roles=uma_authorization,offline_access",
			"--resources=uri=/../api/v1/%61uth/some|roles=non-existent",
			"--openid-provider-retry-count=30",
			"--enable-refresh-tokens=true",
			"--encryption-key=" + testKey,
			"--secure-cookie=false",
			"--enable-register-handler=true",
			"--enable-encrypted-token=false",
			"--enable-id-token-claims=false",
			"--enable-id-token-cookie=false",
			"--enable-user-info-claims=false",
			"--add-claims=email_verified",
			"--add-claims=email",
			"--enable-pkce=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
			"--normalize-path=false",
			"--normalize-path-upstream=false",
			"--merge-slashes=false",
			"--merge-slashes-upstream=false",
			"--path-escaped-slashes=true",
			"--path-escaped-slashes-upstream=true",
			"--enable-logging=true",
			"--verbose=true",
		}

		osArgs := make([]string, 0, 1+len(proxyArgs))
		osArgs = append(osArgs, os.Args[0])
		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Performing standard login", func() {
		It(
			"should login with user/password and logout successfully",
			Label("code_flow"),
			Label("basic_case"),
			Label("normalization_disabled"),
			func(_ context.Context) {
				var err error

				rClient := resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
				rClient.FormData.Add("client_secret", testClientSecret)
				rClient.FormData.Add("client_id", testClient)
				rClient.FormData.Add("grant_type", "client_credentials")
				resp, err := rClient.R().Post(idpRealmURI + "/protocol/openid-connect/token")
				Expect(err).NotTo(HaveOccurred())

				tokenResp := &models.TokenResponse{}
				err = json.Unmarshal(resp.Body(), tokenResp)
				Expect(err).NotTo(HaveOccurred())

				ctx, cancel := context.WithTimeout(context.Background(), tlsTimeout)
				dialer := tls.Dialer{
					Config: &tls.Config{
						ServerName: "localhost",
						RootCAs:    caPool,
						MinVersion: tls.VersionTLS13,
					},
				}

				conn, err := dialer.DialContext(ctx, "tcp", ":"+portNum)
				Expect(err).NotTo(HaveOccurred())

				tricky := "//.%2e/../%2F/api/v1/%61uth/some"
				rawRequest := "GET %s HTTP/1.1\r\n"
				rawRequest += httpLocalHostHeader
				rawRequest += "Cookie: %s=%s; "
				rawRequest += httpBodySeparator

				to := time.Now().Add(60 * time.Second)
				err = conn.SetDeadline(to)
				Expect(err).NotTo(HaveOccurred())

				_, err = fmt.Fprintf(conn, rawRequest, tricky, constant.AccessCookie, tokenResp.AccessToken)
				Expect(err).NotTo(HaveOccurred())

				rawResp := make([]byte, 4096)
				_, err = conn.Read(rawResp)

				cancel()
				conn.Close()

				Expect(err).NotTo(HaveOccurred())
				Expect(strings.Contains(string(rawResp), tricky)).To(BeTrue())
				Expect(strings.Contains(string(rawResp), "GET https://")).NotTo(BeTrue())
				Expect(strings.Contains(string(rawResp), "200")).To(BeTrue())
			},
		)
	})
})

var _ = Describe("Code Flow login/logout all normalization enabled", func() {
	var (
		portNum      string
		proxyAddress string
		server       *http.Server
	)

	errGroup, _ := errgroup.WithContext(context.Background())

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
		var (
			err             error
			upstreamSvcPort string
		)

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup, false, false, false)
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())

		proxyAddress = localURI + portNum

		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--tls-openid-provider-ca-certificate=" + tlsCaCertificate,
			"--tls-openid-provider-client-certificate=" + tlsCertificate,
			"--tls-openid-provider-client-private-key=" + tlsPrivateKey,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--upstream-url=" + localURI + upstreamSvcPort,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--enable-idp-session-check=false",
			"--enable-default-deny=false",
			"--resources=uri=/|roles=uma_authorization,offline_access",
			"--resources=uri=/api/v1/auth/some*|roles=uma_authorization,offline_access",
			"--resources=uri=" + anyURI + "|roles=uma_authorization,offline_access",
			"--resources=uri=/../api/v1/%61uth/some|roles=non-existent",
			"--openid-provider-retry-count=30",
			"--enable-refresh-tokens=true",
			"--encryption-key=" + testKey,
			"--secure-cookie=false",
			"--post-login-redirect-path=" + postLoginRedirectPath,
			"--enable-register-handler=true",
			"--enable-encrypted-token=false",
			"--enable-id-token-claims=true",
			"--enable-id-token-cookie=true",
			"--enable-user-info-claims=true",
			"--add-claims=email_verified",
			"--add-claims=email",
			"--enable-pkce=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
			"--normalize-path=true",
			"--normalize-path-upstream=true",
			"--merge-slashes=true",
			"--merge-slashes-upstream=true",
			"--path-escaped-slashes=false",
			"--path-escaped-slashes-upstream=false",
			"--enable-logging=true",
			"--verbose=true",
		}

		osArgs := make([]string, 0, 1+len(proxyArgs))
		osArgs = append(osArgs, os.Args[0])
		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Performing standard login", func() {
		It(
			"should login with user/password and logout successfully",
			Label("code_flow"),
			Label("basic_case"),
			Label("normalization_enabled"),
			func(_ context.Context) {
				var err error

				ctx, cancel := context.WithTimeout(context.Background(), tlsTimeout)
				dialer := tls.Dialer{
					Config: &tls.Config{
						ServerName: "localhost",
						RootCAs:    caPool,
						MinVersion: tls.VersionTLS13,
					},
				}

				conn, err := dialer.DialContext(ctx, "tcp", ":"+portNum)
				Expect(err).NotTo(HaveOccurred())

				rClient := resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
				resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK, testUser, testPass)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body := resp.Body()
				Expect(strings.Contains(string(body), postLoginRedirectPath)).To(BeTrue())

				jarURI, err := url.Parse(proxyAddress)
				Expect(err).NotTo(HaveOccurred())

				cookiesLogin := rClient.GetClient().Jar.Cookies(jarURI)

				var (
					accessCookieLogin string
					idCookieLogin     string
				)

				for _, cook := range cookiesLogin {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}

					if cook.Name == constant.IDTokenCookie {
						idCookieLogin = cook.Value
					}
				}

				time.Sleep(testAccessTokenExp)

				tricky := "/.%2e/../%2F/api/v1/%61uth/some"
				normalized := "/api/v1/auth/some"
				resp, err = rClient.R().Get(proxyAddress + tricky)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body = resp.Body()
				Expect(strings.Contains(string(body), normalized)).To(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(err).NotTo(HaveOccurred())

				jarURI, err = url.Parse(proxyAddress + tricky)
				Expect(err).NotTo(HaveOccurred())

				cookiesLogin = rClient.GetClient().Jar.Cookies(jarURI)

				for _, cook := range cookiesLogin {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}

					if cook.Name == constant.IDTokenCookie {
						idCookieLogin = cook.Value
					}
				}

				tricky = "/.%2e/../%2F/api/v1/%61uth/some%"
				rawRequest := "GET " + tricky + " HTTP/1.1\r\n"
				repeatRaw := httpLocalHostHeader
				repeatRaw += "Cookie: " + constant.AccessCookie + "=" + accessCookieLogin + "; "
				repeatRaw += constant.IDTokenCookie + "=" + idCookieLogin
				repeatRaw += httpBodySeparator
				rawRequest += repeatRaw

				to := time.Now().Add(10 * time.Second)
				err = conn.SetDeadline(to)
				Expect(err).NotTo(HaveOccurred())

				_, err = conn.Write([]byte(rawRequest))
				Expect(err).NotTo(HaveOccurred())

				rawResp := make([]byte, 1024)
				_, err = conn.Read(rawResp)

				Expect(err).NotTo(HaveOccurred())

				cancel()
				conn.Close()

				Expect(err).NotTo(HaveOccurred())
				Expect(strings.Contains(string(rawResp), "400")).To(BeTrue())

				tricky = "/../api/v1/%61uthh/some"
				resp, err = rClient.R().Get(proxyAddress + tricky)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body = resp.Body()
				Expect(strings.Contains(string(body), normalized)).To(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(err).NotTo(HaveOccurred())

				ctx, cancel = context.WithTimeout(context.Background(), tlsTimeout)
				conn, err = dialer.DialContext(ctx, "tcp", ":"+portNum)
				Expect(err).NotTo(HaveOccurred())

				tricky = "//really/tricky"
				normalized = "/really/tricky"
				rawRequest = "GET " + tricky + " HTTP/1.1\r\n"
				rawRequest += repeatRaw

				_, err = conn.Write([]byte(rawRequest))
				Expect(err).NotTo(HaveOccurred())

				rawResp = make([]byte, 1024)
				_, err = conn.Read(rawResp)

				cancel()
				conn.Close()

				Expect(err).NotTo(HaveOccurred())
				Expect(strings.Contains(string(rawResp), normalized)).To(BeTrue())
				Expect(strings.Contains(string(rawResp), "200")).To(BeTrue())

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
