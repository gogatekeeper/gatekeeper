package session_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/session"
	testsuite_test "github.com/gogatekeeper/gatekeeper/pkg/testsuite"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
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

func TestCompressAndDecompressToken(t *testing.T) {
	tokenGenerator := testsuite_test.NewTestToken("doesntmatter")
	token, err := tokenGenerator.GetToken()
	require.NoError(t, err)

	bufPool := utils.NewLimitedBufferPool(100)
	compressedToken, err := session.CompressToken(token, bufPool)
	assert.NotEmpty(t, compressedToken)
	require.NoError(t, err)
	decompressedToken, err := session.DecompressToken(compressedToken)
	assert.NotEmpty(t, decompressedToken)
	require.NoError(t, err)
	assert.Equal(t, token, decompressedToken)
}

func BenchmarkCompressToken(b *testing.B) {
	tokenGenerator := testsuite_test.NewTestToken("doesntmatter")
	token, err := tokenGenerator.GetToken()
	require.NoError(b, err)

	bufPool := utils.NewLimitedBufferPool(1000)

	for b.Loop() {
		_, _ = session.CompressToken(token, bufPool)
	}
}

func BenchmarkDecompressToken(b *testing.B) {
	tokenGenerator := testsuite_test.NewTestToken("doesntmatter")
	token, err := tokenGenerator.GetToken()
	require.NoError(b, err)

	bufPool := utils.NewLimitedBufferPool(100)
	compressedToken, err := session.CompressToken(token, bufPool)
	assert.NotEmpty(b, compressedToken)
	require.NoError(b, err)

	for b.Loop() {
		_, _ = session.DecompressToken(compressedToken)
	}
}

func TestCompressEncryptAndDecompressEncryptedToken(t *testing.T) {
	tokenGenerator := testsuite_test.NewTestToken("doesntmatter")
	token, err := tokenGenerator.GetToken()
	require.NoError(t, err)

	bufPool := utils.NewLimitedBufferPool(100)
	compressedToken, err := session.EncryptAndCompressToken(token, testsuite_test.TestEncryptionKey, bufPool)
	assert.NotEmpty(t, compressedToken)
	require.NoError(t, err)
	decompressedToken, err := session.DecryptAndDecompressToken(compressedToken, testsuite_test.TestEncryptionKey)
	assert.NotEmpty(t, decompressedToken)
	require.NoError(t, err)
	assert.Equal(t, token, decompressedToken)
}

func BenchmarkEncryptCompressToken(b *testing.B) {
	tokenGenerator := testsuite_test.NewTestToken("doesntmatter")
	token, err := tokenGenerator.GetToken()
	require.NoError(b, err)

	bufPool := utils.NewLimitedBufferPool(1000)

	for b.Loop() {
		_, _ = session.EncryptAndCompressToken(token, testsuite_test.TestEncryptionKey, bufPool)
	}
}

func BenchmarkDecryptDecompressToken(b *testing.B) {
	tokenGenerator := testsuite_test.NewTestToken("doesntmatter")
	token, err := tokenGenerator.GetToken()
	require.NoError(b, err)

	bufPool := utils.NewLimitedBufferPool(100)

	compressedToken, err := session.EncryptAndCompressToken(token, testsuite_test.TestEncryptionKey, bufPool)
	assert.NotEmpty(b, compressedToken)
	require.NoError(b, err)

	for b.Loop() {
		_, _ = session.DecryptAndDecompressToken(compressedToken, testsuite_test.TestEncryptionKey)
	}
}
