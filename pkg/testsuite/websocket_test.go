//go:build !e2e
// +build !e2e

/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package testsuite_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/websocket"
)

// TestWebSocket is used to validate that the proxy reverse proxy WebSocket connections.
func TestWebSocket(t *testing.T) {
	// Setup an upstream service.
	upstream := &FakeUpstreamService{}

	upstreamService := httptest.NewServer(upstream)
	defer upstreamService.Close()

	upstreamURL := upstreamService.URL

	// Setup the proxy.
	cfg := newFakeKeycloakConfig()
	cfg.Upstream = upstreamURL
	res := &authorization.Resource{
		URL:     "/ws",
		Methods: utils.AllHTTPMethods,
		Roles:   []string{"default"},
	}
	cfg.Resources = append(cfg.Resources, res)

	_, proxyServer, proxyURL := newTestProxyService(cfg)
	defer proxyServer.Close()

	resp, _, err := makeTestCodeFlowLogin(proxyURL+FakeAdminURL, false)
	require.NoError(t, err)
	assert.NotNil(t, resp)

	err = resp.Body.Close()
	require.NoError(t, err)

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == constant.AccessCookie {
			cookie = c
		}
	}

	proxyWsURL, err := url.Parse(proxyURL)
	require.NoError(t, err)

	proxyWsURL.Scheme = "ws"

	wsConfig, err := websocket.NewConfig(
		proxyWsURL.String()+"/ws",
		"http://localhost/",
	)

	require.NoError(t, err)
	wsConfig.Header.Set("Cookie", cookie.String())

	wsock, err := websocket.DialConfig(wsConfig)
	require.NoError(t, err)

	request := []byte("hello, world!")
	err = websocket.Message.Send(wsock, request)
	require.NoError(t, err)

	var responseData = make([]byte, 1024)
	err = websocket.Message.Receive(wsock, &responseData)
	require.NoError(t, err)

	responseJSON := fakeUpstreamResponse{}
	err = json.Unmarshal(responseData, &responseJSON)
	require.NoError(t, err)

	assert.Equal(t, "/ws", responseJSON.URI)
}
