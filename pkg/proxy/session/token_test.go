package session_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetRefreshTokenFromCookie(t *testing.T) {
	cases := []struct {
		Cookies  *http.Cookie
		Expected string
		Ok       bool
	}{
		{
			Cookies: &http.Cookie{},
		},
		{
			Cookies: &http.Cookie{
				Name:   "not_a_session_cookie",
				Path:   "/",
				Domain: "127.0.0.1",
			},
		},
		{
			Cookies: &http.Cookie{
				Name:   "kc-state",
				Path:   "/",
				Domain: "127.0.0.1",
				Value:  "refresh_token",
			},
			Expected: "refresh_token",
			Ok:       true,
		},
	}

	for _, testCase := range cases {
		req := &http.Request{
			Method: http.MethodGet,
			Header: make(map[string][]string),
			Host:   "127.0.0.1",
			URL: &url.URL{
				Scheme: "http",
				Host:   "127.0.0.1",
				Path:   "/",
			},
		}
		req.AddCookie(testCase.Cookies)
		token, err := session.GetRefreshTokenFromCookie(req, constant.RefreshCookie)
		switch testCase.Ok {
		case true:
			require.NoError(t, err)
			assert.NotEmpty(t, token)
			assert.Equal(t, testCase.Expected, token)
		default:
			require.Error(t, err)
			assert.Empty(t, token)
		}
	}
}
