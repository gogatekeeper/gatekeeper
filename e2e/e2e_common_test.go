package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-chi/chi/v5/middleware"
	resty "github.com/go-resty/resty/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	keycloakcore "github.com/gogatekeeper/gatekeeper/pkg/keycloak/proxy/core"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy"
	testsuite_test "github.com/gogatekeeper/gatekeeper/pkg/testsuite"
	. "github.com/onsi/ginkgo/v2" //nolint:revive //we want to use it for ginkgo
	. "github.com/onsi/gomega"    //nolint:revive //we want to use it for gomega
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
	testKey                 = "trksjblzqsujshex"
	timeout                 = time.Second * 300
	tlsTimeout              = 10 * time.Second
	testAccessTokenExp      = 5 * time.Second
	idpURI                  = "https://localhost:8443"
	localURI                = "https://localhost:"
	httpLocalURI            = "http://localhost:"
	localAddr               = "localhost:"
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
	testCompressionType     = "deflate"
	testCookieValue         = "test-cookie"

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
	redisSentinel1Port      = "8000"
	redisSentinel2Port      = "8001"
	redisSentinel3Port      = "8002"
	postLoginRedirectPath   = "/post/login/path"
	pkceCookieName          = "TESTPKCECOOKIE"
	umaCookieName           = "TESTUMACOOKIE"
	testExternalURI         = "google.com"
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
	var (
		minPort int64 = 1024
		maxPort int64 = 65000
	)

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

func addHeaderCompressMiddlware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			req.Header.Set("Accept-Encoding", testCompressionType)
			next.ServeHTTP(wrt, req)
		})
	}
}

func startAndWaitTestUpstream(
	errGroup *errgroup.Group,
	clientAuth bool,
	compress bool,
	forceCompressionType bool,
) (*http.Server, string) {
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

	// to simplify and don't have separate key, cert for server and separate key, cert for client
	// we use same key, cert for server side and also for client auth
	clientPair := tlsCert

	if clientAuth {
		tlsConfig.ClientCAs = caPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	listener = tls.NewListener(listener, tlsConfig)

	var handler http.Handler = &testsuite_test.FakeUpstreamService{}

	if compress {
		addHeaderComp := addHeaderCompressMiddlware()
		compressMid := middleware.Compress(constant.HTTPCompressionLevel)

		handlerWithCompress := compressMid(&testsuite_test.FakeUpstreamService{})
		if forceCompressionType {
			handler = addHeaderComp(handlerWithCompress)
		} else {
			handler = handlerWithCompress
		}
	}

	testTimeout := 30 * time.Second
	server := &http.Server{
		Addr:              listener.Addr().String(),
		Handler:           handler,
		TLSConfig:         tlsConfig,
		WriteTimeout:      testTimeout,
		ReadTimeout:       testTimeout,
		ReadHeaderTimeout: testTimeout,
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

		if clientAuth {
			dialer.Config.Certificates = []tls.Certificate{clientPair}
		}

		conn, err := dialer.DialContext(ctx, "tcp", ":"+port)

		cancel()
		Expect(err).NotTo(HaveOccurred())

		conn.Close()

		return nil
	}, timeout, tlsTimeout).Should(Succeed())

	return server, port
}

//nolint:cyclop
func startAndWaitTestRawUpstream(
	errGroup *errgroup.Group,
	clientAuth bool,
) (*net.Listener, string) {
	//nolint:gosec
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	Expect(err).NotTo(HaveOccurred())

	tlsCert, err := tls.LoadX509KeyPair(tlsCertificate, tlsPrivateKey)
	Expect(err).NotTo(HaveOccurred())

	tlsConfig := &tls.Config{
		Certificates:             []tls.Certificate{tlsCert},
		PreferServerCipherSuites: true,
		NextProtos:               []string{"http/1.1"},
		MinVersion:               tls.VersionTLS13,
	}

	// to simplify and don't have separate key, cert for server and separate key, cert for client
	// we use same key, cert for server side and also for client auth
	clientPair := tlsCert

	if clientAuth {
		tlsConfig.ClientCAs = caPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	listener = tls.NewListener(listener, tlsConfig)

	errGroup.Go(func() error {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return nil
				}

				return err
			}

			defer conn.Close()

			err = conn.SetDeadline(time.Now().Add(60 * time.Second))
			if err != nil {
				return err
			}

			var out []byte

			for {
				buf := make([]byte, 1024)

				numBytes, err := conn.Read(buf)
				if err != nil && !errors.Is(err, io.EOF) {
					return err
				}

				out = append(out, buf...)

				if numBytes < 1024 {
					break
				}

				if errors.Is(err, io.EOF) {
					break
				}
			}

			_, err = fmt.Fprintf(
				conn,
				"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: application/text\r\n\r\n%s",
				len(string(out)),
				string(out),
			)
			if err != nil {
				return err
			}

			conn.Close()
		}
	})

	netParts := strings.Split(listener.Addr().String(), ":")
	port := netParts[len(netParts)-1]

	Eventually(func(_ Gomega) error {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		dialer := tls.Dialer{
			Config: &tls.Config{
				ServerName: "localhost",
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS13,
			},
		}

		if clientAuth {
			dialer.Config.Certificates = []tls.Certificate{clientPair}
		}

		conn, err := dialer.DialContext(ctx, "tcp", ":"+port)

		Expect(err).NotTo(HaveOccurred())
		_, err = fmt.Fprintf(conn, "ping\n")
		Expect(err).NotTo(HaveOccurred())

		cancel()
		conn.Close()

		return nil
	}, timeout, tlsTimeout).Should(Succeed())

	return &listener, port
}
