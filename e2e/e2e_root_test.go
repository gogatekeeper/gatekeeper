package e2e_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	resty "github.com/go-resty/resty/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/session"
	. "github.com/onsi/ginkgo/v2" //nolint:revive //we want to use it for ginkgo
	. "github.com/onsi/gomega"    //nolint:revive //we want to use it for gomega
	"golang.org/x/sync/errgroup"
)

var _ = Describe("Code Flow login/logout compression and encryption Auth Scheme Cookie", func() {
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

		tmpDir := os.TempDir()
		tmpDirSlash := tmpDir + "/"
		tlsCaCertificate := strings.TrimPrefix(tlsCaCertificate, tmpDirSlash)
		tlsCertificate := strings.TrimPrefix(tlsCertificate, tmpDirSlash)
		tlsPrivateKey := strings.TrimPrefix(tlsPrivateKey, tmpDirSlash)

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
			"--resources=uri=/*|roles=uma_authorization,offline_access",
			"--resources=uri=" + testPath + "|no-redirect=true",
			"--openid-provider-retry-count=30",
			"--enable-refresh-tokens=true",
			"--encryption-key=" + testKey,
			"--secure-cookie=false",
			"--post-login-redirect-path=" + postLoginRedirectPath,
			"--enable-register-handler=true",
			"--enable-encrypted-token=true",
			"--enable-id-token-cookie=true",
			"--enable-user-info-claims=true",
			"--add-claims=email_verified",
			"--add-claims=email",
			"--enable-pkce=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
			"--enable-compress-token=true",
			"--compress-token-only-auth-scheme=cookie",
			"--enable-logout-redirect=true",
			"--post-logout-redirect-uri=https://" + testExternalURI,
			"--verbose=true",
			"--file-root=" + tmpDir,
		}

		osArgs := make([]string, 0, 1+len(proxyArgs))
		osArgs = append(osArgs, os.Args[0])
		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Performing standard login", func() {
		It("should login with user/password and logout successfully",
			Label("code_flow"),
			Label("compression_auth_scheme"),
			Label("auth_scheme_cookie"),
			func(_ context.Context) {
				var err error

				rClient := resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
				noCookieClient := rClient.Clone()
				resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK, testUser, testPass)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body := resp.Body()
				Expect(strings.Contains(string(body), postLoginRedirectPath)).To(BeTrue())

				jarURI, err := url.Parse(proxyAddress)
				Expect(err).NotTo(HaveOccurred())

				cookiesLogin := rClient.GetClient().Jar.Cookies(jarURI)

				var (
					accessCookieLogin  string
					refreshCookieLogin string
				)

				for _, cook := range cookiesLogin {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}

					if cook.Name == constant.RefreshCookie {
						refreshCookieLogin = cook.Value
					}
				}

				accessCookieLogin, err = session.DecryptAndDecompressToken(accessCookieLogin, testKey)
				Expect(err).NotTo(HaveOccurred())
				_, err = jwt.ParseSigned(accessCookieLogin, constant.SignatureAlgs[:])
				Expect(err).NotTo(HaveOccurred())

				refreshCookieLogin, err = session.DecryptAndDecompressToken(refreshCookieLogin, testKey)
				Expect(err).NotTo(HaveOccurred())
				_, err = jwt.ParseSigned(refreshCookieLogin, constant.SignatureAlgs[:])
				Expect(err).NotTo(HaveOccurred())

				time.Sleep(testAccessTokenExp)

				resp, err = rClient.R().Get(proxyAddress + anyURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body = resp.Body()
				Expect(strings.Contains(string(body), anyURI)).To(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(err).NotTo(HaveOccurred())

				cookiesAfterRefresh := rClient.GetClient().Jar.Cookies(jarURI)

				var (
					accessCookieAfterRefresh  string
					refreshCookieAfterRefresh string
					testCookie                string
				)

				for _, cook := range cookiesAfterRefresh {
					if cook.Name == constant.AccessCookie {
						accessCookieAfterRefresh = cook.Value
					}

					if cook.Name == constant.RefreshCookie {
						refreshCookieAfterRefresh = cook.Value
					}

					if cook.Name == testCookieValue {
						testCookie = cook.Value
					}
				}

				Expect(testCookie).To(Equal("test_value"))

				accessCookieAfterRefresh, err = session.DecryptAndDecompressToken(accessCookieAfterRefresh, testKey)
				Expect(err).NotTo(HaveOccurred())
				_, err = jwt.ParseSigned(accessCookieAfterRefresh, constant.SignatureAlgs[:])
				Expect(err).NotTo(HaveOccurred())
				Expect(accessCookieLogin).NotTo(Equal(accessCookieAfterRefresh))

				refreshCookieAfterRefresh, err = session.DecryptAndDecompressToken(refreshCookieAfterRefresh, testKey)
				Expect(err).NotTo(HaveOccurred())
				_, err = jwt.ParseSigned(refreshCookieAfterRefresh, constant.SignatureAlgs[:])
				Expect(err).NotTo(HaveOccurred())

				resp, err = rClient.R().Get(proxyAddress + anyURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

				body = resp.Body()

				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(strings.Contains(string(body), anyURI)).To(BeTrue())

				accessCookieAfterRefresh, err = encryption.EncodeText(accessCookieAfterRefresh, testKey)
				Expect(err).NotTo(HaveOccurred())

				resp, err = noCookieClient.R().SetAuthToken(accessCookieAfterRefresh).Get(proxyAddress + testPath)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

				body = resp.Body()

				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(strings.Contains(string(body), testPath)).To(BeTrue())

				resp, err = noCookieClient.R().SetAuthToken(accessCookieAfterRefresh).Get(proxyAddress + anyURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

				body = resp.Body()

				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(strings.Contains(string(body), anyURI)).To(BeTrue())

				//nolint:gosec
				rClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
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
