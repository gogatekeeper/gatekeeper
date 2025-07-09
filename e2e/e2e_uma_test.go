package e2e_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"strings"
	"time"

	resty "github.com/go-resty/resty/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	. "github.com/onsi/ginkgo/v2" //nolint:revive //we want to use it for ginkgo
	. "github.com/onsi/gomega"    //nolint:revive //we want to use it for gomega
	"golang.org/x/sync/errgroup"
)

var _ = Describe("UMA Code Flow authorization", func() {
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

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup, false)
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum
		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--openid-provider-ca=" + tlsCaCertificate,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + umaTestClient,
			"--client-secret=" + umaTestClientSecret,
			"--upstream-url=" + localURI + upstreamSvcPort,
			"--no-redirects=false",
			"--verbose=true",
			"--enable-uma=true",
			"--cookie-uma-name=" + umaCookieName,
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
			"--enable-encrypted-token=false",
			"--enable-pkce=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Accessing resource, where user is allowed to access", func() {
		It("should login with user/password and logout successfully", func(_ context.Context) {
			var err error
			rClient := resty.New()
			rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
			resp := codeFlowLogin(rClient, proxyAddress+umaAllowedPath, http.StatusOK, testUser, testPass)
			Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

			body := resp.Body()
			Expect(strings.Contains(string(body), umaCookieName)).To(BeTrue())

			By("Accessing not allowed path")
			resp, err = rClient.R().Get(proxyAddress + umaForbiddenPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
			Expect(strings.Contains(string(body), umaCookieName)).To(BeFalse())

			resp, err = rClient.R().Get(proxyAddress + logoutURI)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
			resp, _ = rClient.R().Get(proxyAddress + umaAllowedPath)
			Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
		})
	})

	When("Accessing resource, which does not exist", func() {
		It("should be forbidden without permission ticket", func(_ context.Context) {
			rClient := resty.New()
			rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
			resp := codeFlowLogin(rClient, proxyAddress+umaNonExistentPath, http.StatusForbidden, testUser, testPass)

			body := resp.Body()
			Expect(strings.Contains(string(body), umaCookieName)).To(BeFalse())
		})
	})

	When("Accessing resource, which exists but user is not allowed and then allowed resource", func() {
		It("should be forbidden and then allowed", func(_ context.Context) {
			var err error
			rClient := resty.New()
			rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
			resp := codeFlowLogin(rClient, proxyAddress+umaForbiddenPath, http.StatusForbidden, testUser, testPass)

			body := resp.Body()
			Expect(strings.Contains(string(body), umaCookieName)).To(BeFalse())

			By("Accessing allowed resource")
			resp, err = rClient.R().Get(proxyAddress + umaAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))
			Expect(strings.Contains(string(body), umaCookieName)).To(BeFalse())

			By("Accessing allowed resource one more time, checking uma cookie set")
			resp, err = rClient.R().Get(proxyAddress + umaAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))
			Expect(strings.Contains(string(body), umaCookieName)).To(BeTrue())
		})
	})
})

var _ = Describe("UMA Code Flow authorization with method scope", func() {
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

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup, false)
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum
		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--openid-provider-ca=" + tlsCaCertificate,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + umaTestClient,
			"--client-secret=" + umaTestClientSecret,
			"--upstream-url=" + localURI + upstreamSvcPort,
			"--no-redirects=false",
			"--enable-uma=true",
			"--enable-uma-method-scope=true",
			"--cookie-uma-name=" + umaCookieName,
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
			"--verbose=true",
			"--enable-logging=true",
			"--enable-encrypted-token=false",
			"--enable-pkce=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Accessing resource, where user is allowed to access and then not allowed resource", func() {
		It(
			"should login with user/password, don't access forbidden resource and logout successfully",
			func(_ context.Context) {
				var err error
				rClient := resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
				resp := codeFlowLogin(rClient, proxyAddress+umaMethodAllowedPath, http.StatusOK, testUser, testPass)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

				body := resp.Body()
				Expect(strings.Contains(string(body), umaCookieName)).To(BeTrue())

				By("Accessing not allowed method")
				resp, err = rClient.R().Post(proxyAddress + umaMethodAllowedPath)
				body = resp.Body()
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
				Expect(strings.Contains(string(body), umaCookieName)).To(BeFalse())

				resp, err = rClient.R().Get(proxyAddress + logoutURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
				resp, _ = rClient.R().Get(proxyAddress + umaAllowedPath)
				Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
			})
	})
})

var _ = Describe("UMA no-redirects authorization with forwarding client credentials grant", func() {
	var portNum string
	var proxyAddress string
	var fwdPortNum string
	var fwdProxyAddress string
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

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup, false)
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		fwdPortNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum
		fwdProxyAddress = httpLocalURI + fwdPortNum
		osArgs := []string{os.Args[0]}
		fwdOsArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--openid-provider-ca=" + tlsCaCertificate,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + umaTestClient,
			"--client-secret=" + umaTestClientSecret,
			"--upstream-url=" + localURI + upstreamSvcPort,
			"--no-redirects=true",
			"--enable-uma=true",
			"--enable-uma-method-scope=true",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--enable-idp-session-check=false",
			"--enable-encrypted-token=false",
			"--enable-pkce=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
		}

		fwdProxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--openid-provider-ca=" + tlsCaCertificate,
			"--listen=" + allInterfaces + fwdPortNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--enable-uma=true",
			"--enable-uma-method-scope=true",
			"--enable-forwarding=true",
			"--enable-authorization-header=true",
			"--forwarding-grant-type=client_credentials",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--enable-encrypted-token=false",
			"--enable-pkce=false",
			"--tls-forwarding-ca-certificate=" + tlsCaCertificate,
			"--tls-forwarding-ca-private-key=" + tlsCaKey,
			"--upstream-ca=" + tlsCaCertificate,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
		fwdOsArgs = append(fwdOsArgs, fwdProxyArgs...)
		startAndWait(fwdPortNum, fwdOsArgs)
	})

	When("Accessing resource, where user is allowed to access and then not allowed resource", func() {
		It("should login with client secret, don't access forbidden resource", func(_ context.Context) {
			rClient := resty.New().SetRedirectPolicy(resty.NoRedirectPolicy())
			rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
			rClient.SetProxy(fwdProxyAddress)
			resp, err := rClient.R().Get(proxyAddress + umaFwdMethodAllowedPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			body := resp.Body()
			Expect(strings.Contains(string(body), umaFwdMethodAllowedPath)).To(BeTrue())

			By("Accessing resource without access for client id")
			resp, err = rClient.R().Get(proxyAddress + umaAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
			Expect(strings.Contains(string(body), umaAllowedPath)).To(BeFalse())

			By("Accessing not allowed method")
			resp, err = rClient.R().Post(proxyAddress + umaFwdMethodAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
			Expect(strings.Contains(string(body), umaFwdMethodAllowedPath)).To(BeFalse())
		})
	})
})

var _ = Describe("UMA no-redirects authorization with forwarding direct access grant", func() {
	var portNum string
	var proxyAddress string
	var fwdPortNum string
	var fwdProxyAddress string
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

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup, false)
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		fwdPortNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum
		fwdProxyAddress = httpLocalURI + fwdPortNum
		osArgs := []string{os.Args[0]}
		fwdOsArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--openid-provider-ca=" + tlsCaCertificate,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + umaTestClient,
			"--client-secret=" + umaTestClientSecret,
			"--upstream-url=" + localURI + upstreamSvcPort,
			"--no-redirects=true",
			"--enable-uma=true",
			"--enable-uma-method-scope=true",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--verbose=true",
			"--enable-idp-session-check=false",
			"--enable-encrypted-token=false",
			"--enable-pkce=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
		}

		fwdProxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--openid-provider-ca=" + tlsCaCertificate,
			"--listen=" + allInterfaces + fwdPortNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--forwarding-username=" + testUser,
			"--forwarding-password=" + testPass,
			"--enable-uma=true",
			"--enable-uma-method-scope=true",
			"--enable-forwarding=true",
			"--enable-authorization-header=true",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--enable-encrypted-token=false",
			"--enable-pkce=false",
			"--tls-forwarding-ca-certificate=" + tlsCaCertificate,
			"--tls-forwarding-ca-private-key=" + tlsCaKey,
			"--upstream-ca=" + tlsCaCertificate,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
		fwdOsArgs = append(fwdOsArgs, fwdProxyArgs...)
		startAndWait(fwdPortNum, fwdOsArgs)
	})

	When("Accessing resource, where user is allowed to access and then not allowed resource", func() {
		It("should login with user/password, don't access forbidden resource", func(_ context.Context) {
			rClient := resty.New().SetRedirectPolicy(resty.NoRedirectPolicy())
			rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
			rClient.SetProxy(fwdProxyAddress)
			resp, err := rClient.R().Get(proxyAddress + umaMethodAllowedPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			body := resp.Body()
			Expect(strings.Contains(string(body), umaMethodAllowedPath)).To(BeTrue())
			Expect(resp.Header().Get(constant.UMAHeader)).NotTo(BeEmpty())

			By("Repeating access to allowed resource, we verify that uma was saved and reused")
			resp, err = rClient.R().Get(proxyAddress + umaMethodAllowedPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			body = resp.Body()
			GinkgoLogr.Info(string(body))
			Expect(strings.Contains(string(body), umaMethodAllowedPath)).To(BeTrue())
			Expect(resp.Header().Get(constant.UMAHeader)).To(BeEmpty())
			// as first request should return uma token in header, it should be
			// saved in forwarding rpt structure and sent also in this request
			// so we should see it in response body
			Expect(strings.Contains(string(body), constant.UMAHeader)).To(BeTrue())

			By("Accessing resource without access for user")
			resp, err = rClient.SetTimeout(1 * time.Hour).R().Get(proxyAddress + umaForbiddenPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
			Expect(strings.Contains(string(body), umaForbiddenPath)).To(BeFalse())
			Expect(resp.Header().Get(constant.UMATicketHeader)).NotTo(BeEmpty())

			By("Accessing not allowed method")
			resp, err = rClient.R().Post(proxyAddress + umaMethodAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
			Expect(strings.Contains(string(body), umaMethodAllowedPath)).To(BeFalse())
		})
	})
})

var _ = Describe("UMA Code Flow, NOPROXY authorization with method scope", func() {
	var portNum string
	var proxyAddress string
	umaCookieName := "TESTUMACOOKIE"
	// server := httptest.NewServer(&testsuite.FakeUpstreamService{})

	BeforeEach(func() {
		var err error
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum
		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=300s",
			"--openid-provider-ca=" + tlsCaCertificate,
			"--listen=" + allInterfaces + portNum,
			"--client-id=" + umaTestClient,
			"--client-secret=" + umaTestClientSecret,
			"--no-redirects=false",
			"--enable-uma=true",
			"--enable-uma-method-scope=true",
			"--no-proxy=true",
			"--cookie-uma-name=" + umaCookieName,
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
			"--verbose=true",
			"--enable-logging=true",
			"--enable-encrypted-token=false",
			"--enable-pkce=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Accessing allowed resource", func() {
		It("should be allowed and logout successfully", func(_ context.Context) {
			var err error
			rClient := resty.New()
			rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
			rClient.SetHeaders(map[string]string{
				constant.HeaderXForwardedProto:  "https",
				constant.HeaderXForwardedHost:   strings.Split(proxyAddress, "//")[1],
				constant.HeaderXForwardedURI:    umaMethodAllowedPath,
				constant.HeaderXForwardedMethod: "GET",
			})
			resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK, testUser, testPass)
			Expect(resp.Header().Get(constant.AuthorizationHeader)).ToNot(BeEmpty())

			resp, err = rClient.R().Get(proxyAddress + logoutURI)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
			resp, _ = rClient.R().Get(proxyAddress + umaAllowedPath)
			Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
		})
	})

	When("Accessing not allowed resource", func() {
		It("should be forbidden", func(_ context.Context) {
			rClient := resty.New()
			rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
			rClient.SetHeaders(map[string]string{
				constant.HeaderXForwardedProto:  "https",
				constant.HeaderXForwardedHost:   strings.Split(proxyAddress, "//")[1],
				constant.HeaderXForwardedURI:    umaMethodAllowedPath,
				constant.HeaderXForwardedMethod: "POST",
			})
			resp := codeFlowLogin(rClient, proxyAddress, http.StatusForbidden, testUser, testPass)
			Expect(resp.Header().Get(constant.AuthorizationHeader)).To(BeEmpty())
		})
	})

	When("Accessing resource without X-Forwarded headers", func() {
		It("should be forbidden", func(_ context.Context) {
			rClient := resty.New()
			rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})
			rClient.SetHeaders(map[string]string{
				constant.HeaderXForwardedProto: "https",
				constant.HeaderXForwardedHost:  strings.Split(proxyAddress, "//")[1],
				constant.HeaderXForwardedURI:   umaMethodAllowedPath,
			})
			resp := codeFlowLogin(rClient, proxyAddress, http.StatusForbidden, testUser, testPass)
			Expect(resp.Header().Get(constant.AuthorizationHeader)).To(BeEmpty())
		})
	})
})
