package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"

	resty "github.com/go-resty/resty/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gorilla/websocket"
	. "github.com/onsi/ginkgo/v2" //nolint:revive //we want to use it for ginkgo
	. "github.com/onsi/gomega"    //nolint:revive //we want to use it for gomega
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/sync/errgroup"
)

var _ = Describe("NoRedirects Websocket login/logout", func() {
	var portNum string
	var proxyAddress string
	var proxyAddr string
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

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup, false, false, false)
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum
		proxyAddr = localAddr + portNum

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

		osArgs := make([]string, 0, 1+len(proxyArgs))
		osArgs = append(osArgs, os.Args[0])
		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Performing standard login", func() {
		It("should login with service account and logout successfully",
			Label("api_flow"),
			Label("websocket"),
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

				wSocketURL := url.URL{Scheme: "wss", Host: proxyAddr, Path: "/"}

				var headers http.Header = map[string][]string{}
				headers.Add("Cookie", "kc-access="+respToken.AccessToken)

				websocket.DefaultDialer.TLSClientConfig = &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13}
				wConn, _, err := websocket.DefaultDialer.Dial(wSocketURL.String(), headers)
				Expect(err).NotTo(HaveOccurred())

				defer wConn.Close()

				messageNotPresent := errors.New("message not present in websocket response")

				testErrGroup, _ := errgroup.WithContext(context.Background())
				testErrGroup.Go(func() error {
					_, message, err := wConn.ReadMessage()
					if err != nil {
						return err
					}

					if !bytes.Contains(message, []byte(constant.Author)) {
						return messageNotPresent
					}

					return nil
				})

				err = wConn.WriteMessage(websocket.TextMessage, []byte(constant.Author))
				Expect(err).NotTo(HaveOccurred())

				err = testErrGroup.Wait()
				Expect(err).NotTo(HaveOccurred())

				rClient = resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})

				request := rClient.R().SetAuthToken(respToken.AccessToken)
				resp, err := request.Get(proxyAddress + logoutURI)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
			},
		)
	})

	When("Performing websocket connection on http backend", func() {
		It("websocket upgrade should fail",
			Label("api_flow"),
			Label("websocket_fail"),
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

				wSocketURL := url.URL{Scheme: "wss", Host: proxyAddr, Path: "/"}

				var headers http.Header = map[string][]string{}
				headers.Add("Cookie", "kc-access="+respToken.AccessToken)
				headers.Add("Websocketfail", "true")

				websocket.DefaultDialer.TLSClientConfig = &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13}
				wConn, res, err := websocket.DefaultDialer.Dial(wSocketURL.String(), headers)

				Expect(res.StatusCode).To(Equal(http.StatusOK))
				Expect(err).To(HaveOccurred())
				Expect(wConn).To(BeNil())

				// testing if normal http request after failed websocket handshake works properly, not missing
				// headers
				rClient = resty.New()
				rClient.SetTLSClientConfig(&tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13})

				request := rClient.SetRedirectPolicy(
					resty.NoRedirectPolicy()).R().SetAuthToken(respToken.AccessToken)
				resp, err := request.Get(proxyAddress)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(resp.Body()).To(ContainSubstring(constant.AuthorizationHeader))
			},
		)
	})
})

var _ = Describe("Code Flow websocket login/logout", func() {
	var portNum string
	var proxyAddress string
	var proxyAddr string
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

		server, upstreamSvcPort = startAndWaitTestUpstream(errGroup, false, false, false)
		portNum, err = generateRandomPort()
		Expect(err).NotTo(HaveOccurred())
		proxyAddress = localURI + portNum
		proxyAddr = localAddr + portNum

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
			"--openid-provider-retry-count=30",
			"--enable-refresh-tokens=true",
			"--encryption-key=" + testKey,
			"--secure-cookie=false",
			"--post-login-redirect-path=" + postLoginRedirectPath,
			"--enable-register-handler=true",
			"--enable-encrypted-token=false",
			"--enable-pkce=false",
			"--tls-cert=" + tlsCertificate,
			"--tls-private-key=" + tlsPrivateKey,
			"--upstream-ca=" + tlsCaCertificate,
		}

		osArgs := make([]string, 0, 1+len(proxyArgs))
		osArgs = append(osArgs, os.Args[0])
		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Performing standard websocket login", func() {
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

				wSocketURL := url.URL{Scheme: "wss", Host: proxyAddr, Path: "/"}

				var headers http.Header = map[string][]string{}
				headers.Add("Cookie", "kc-access="+accessCookieLogin)

				websocket.DefaultDialer.TLSClientConfig = &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13}
				wConn, _, err := websocket.DefaultDialer.Dial(wSocketURL.String(), headers)
				Expect(err).NotTo(HaveOccurred())

				defer wConn.Close()

				messageNotPresent := errors.New("message not present in websocket response")

				testErrGroup, _ := errgroup.WithContext(context.Background())
				testErrGroup.Go(func() error {
					_, message, err := wConn.ReadMessage()
					if err != nil {
						return err
					}

					if !bytes.Contains(message, []byte(constant.Author)) {
						return messageNotPresent
					}

					return nil
				})

				err = wConn.WriteMessage(websocket.TextMessage, []byte(constant.Author))
				Expect(err).NotTo(HaveOccurred())

				err = testErrGroup.Wait()
				Expect(err).NotTo(HaveOccurred())

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

	When("Performing websocket connection on http backend", func() {
		It("websocket upgrade should fail",
			Label("code_flow"),
			Label("websocket"),
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

				wSocketURL := url.URL{Scheme: "wss", Host: proxyAddr, Path: "/"}

				var headers http.Header = map[string][]string{}
				headers.Add("Cookie", "kc-access="+accessCookieLogin)
				headers.Add("Websocketfail", "true")

				websocket.DefaultDialer.TLSClientConfig = &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS13}
				wConn, res, err := websocket.DefaultDialer.Dial(wSocketURL.String(), headers)

				Expect(res.StatusCode).To(Equal(http.StatusOK))
				Expect(err).To(HaveOccurred())
				Expect(wConn).To(BeNil())

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
