package e2e_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"strings"

	resty "github.com/go-resty/resty/v2"
	. "github.com/onsi/ginkgo/v2" //nolint:revive //we want to use it for ginkgo
	. "github.com/onsi/gomega"    //nolint:revive //we want to use it for gomega
	"golang.org/x/sync/errgroup"
)

var _ = Describe("Code Flow PKCE login/logout with mTLS REDIS", func() {
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
			"--encryption-key=" + testKey,
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
			"--store-url=rediss://" + redisUser + ":" + redisPass + "@localhost:" + redisMasterPort + "/0",
			"--tls-store-ca-certificate=" + tlsCaCertificate,
			"--tls-store-client-certificate=" + tlsCertificate,
			"--tls-store-client-private-key=" + tlsPrivateKey,
		}

		osArgs := make([]string, 0, 1+len(proxyArgs))
		osArgs = append(osArgs, os.Args[0])
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

var _ = Describe("Code Flow PKCE login/logout with mTLS REDIS CLUSTER", func() {
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

		redisClusterURL := "rediss://" + redisUser + ":" + redisClusterPass + "@127.0.0.1:" + redisClusterMaster1Port
		redisClusterURL += "?dial_timeout=3&read_timeout=6s&addr=127.0.0.1:" + redisClusterMaster2Port
		redisClusterURL += "&addr=127.0.0.1:" + redisClusterMaster3Port

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
			"--encryption-key=" + testKey,
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
			"--store-url=" + redisClusterURL,
			"--enable-store-ha=true",
			"--tls-store-ca-certificate=" + tlsCaCertificate,
			"--tls-store-client-certificate=" + tlsCertificate,
			"--tls-store-client-private-key=" + tlsPrivateKey,
		}

		osArgs := make([]string, 0, 1+len(proxyArgs))
		osArgs = append(osArgs, os.Args[0])
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

var _ = Describe("Code Flow PKCE login/logout with mTLS REDIS SENTINEL", func() {
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

		redisSentinelURL := "rediss://" + redisUser + ":" + redisClusterPass + "@127.0.0.1:" + redisSentinel1Port
		redisSentinelURL += "?master_name=mymaster&dial_timeout=3&read_timeout=6s&addr=127.0.0.1:" + redisSentinel2Port
		redisSentinelURL += "&addr=127.0.0.1:" + redisSentinel3Port + "&username=default&password=" + redisClusterPass

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
			"--encryption-key=" + testKey,
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
			"--store-url=" + redisSentinelURL,
			"--enable-store-ha=true",
			"--tls-store-ca-certificate=" + tlsCaCertificate,
			"--tls-store-client-certificate=" + tlsCertificate,
			"--tls-store-client-private-key=" + tlsPrivateKey,
		}

		osArgs := make([]string, 0, 1+len(proxyArgs))
		osArgs = append(osArgs, os.Args[0])
		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
		waitForPort(redisSentinel1Port)
		waitForPort(redisSentinel2Port)
		waitForPort(redisSentinel3Port)
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
