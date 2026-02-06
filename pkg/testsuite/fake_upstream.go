package testsuite_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gorilla/websocket"
)

// FakeUpstreamResponse is the response from fake upstream.
type FakeUpstreamResponse struct {
	URI     string      `json:"uri"`
	Method  string      `json:"method"`
	Address string      `json:"address"`
	Headers http.Header `json:"headers"`
	Body    string      `json:"body"`
}

// FakeUpstreamService acts as a fake upstream service, returns the headers and request.
type FakeUpstreamService struct{}

//nolint:cyclop
func (f *FakeUpstreamService) ServeHTTP(wrt http.ResponseWriter, req *http.Request) {
	upgrade := strings.ToLower(req.Header.Get(constant.HeaderUpgrade))
	websocketFail := strings.ToLower(req.Header.Get("Websocketfail"))

	switch {
	case websocketFail == "true":
		wrt.WriteHeader(http.StatusOK)
		return
	case upgrade == "websocket":
		var headers http.Header = map[string][]string{}
		headers.Add(TestProxyAccepted, "true")

		upgrader := websocket.Upgrader{
			CheckOrigin: func(_ *http.Request) bool {
				return true
			},
		}

		wsock, err := upgrader.Upgrade(wrt, req, headers)
		if err != nil {
			wrt.WriteHeader(http.StatusInternalServerError)
			return
		}

		defer wsock.Close()

		_, message, err := wsock.ReadMessage()
		if err != nil {
			wrt.WriteHeader(http.StatusInternalServerError)
			return
		}

		content, err := json.Marshal(&FakeUpstreamResponse{
			URI:     req.RequestURI,
			Method:  req.Method,
			Address: req.RemoteAddr,
			Headers: req.Header,
			Body:    string(message),
		})
		if err != nil {
			wrt.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = wsock.WriteMessage(websocket.BinaryMessage, content)
		if err != nil {
			wrt.WriteHeader(http.StatusInternalServerError)
			return
		}
	default:
		reqBody, err := io.ReadAll(req.Body)
		if err != nil {
			wrt.WriteHeader(http.StatusInternalServerError)
		}

		var delay int

		rawDelay := req.Header.Get("Delay")
		if rawDelay != "" {
			delay, err = strconv.Atoi(rawDelay)
			if err != nil {
				wrt.WriteHeader(http.StatusInternalServerError)
			}
		}

		if delay > 0 {
			// Sleep for the specified duration
			// This is to simulate a slow upstream service
			<-time.After(time.Duration(delay) * time.Second)
		}

		wrt.Header().Set(TestProxyAccepted, "true")
		wrt.Header().Set(constant.HeaderContentType, "application/json")

		content, err := json.Marshal(&FakeUpstreamResponse{
			// r.RequestURI is what was received by the proxy.
			// r.URL.String() is what is actually sent to the upstream service.
			// KEYCLOAK-10864, KEYCLOAK-11276, KEYCLOAK-13315
			URI:     req.URL.String(),
			Method:  req.Method,
			Address: req.RemoteAddr,
			Headers: req.Header,
			Body:    string(reqBody),
		})
		if err != nil {
			wrt.WriteHeader(http.StatusInternalServerError)
		} else {
			wrt.WriteHeader(http.StatusOK)
		}

		_, _ = wrt.Write(content)
	}
}

// commented out see TestUpstreamProxy test comment
// func createTestProxy() (*http.Server, net.Listener, error) {
// 	proxy := goproxy.NewProxyHttpServer()
// 	proxy.OnRequest().DoFunc(
// 		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
// 			r.Header.Set(TestProxyHeaderKey, TestProxyHeaderVal)
// 			return r, nil
// 		},
// 	)
// 	proxyHTTPServer := &http.Server{
// 		Handler: proxy,
// 	}
// 	ln, err := net.Listen("tcp", randomLocalHost)
// 	if err != nil {
//nolint:dupword
// 		return nil, nil, err
// 	}
// 	return proxyHTTPServer, ln, nil
// }
