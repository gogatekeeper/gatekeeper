package middleware_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	gmiddleware "github.com/gogatekeeper/gatekeeper/pkg/proxy/middleware"
)

func RouteHeadersDenyTestMiddleware() func(http.Handler) http.Handler {
	return func(_ http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, _ *http.Request) {
			wrt.WriteHeader(http.StatusForbidden)
		})
	}
}

func TestRouteHeadersMiddleware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		requestHeaders map[string]string
		name           string
		header         string
		match          string
		matchType      gmiddleware.MatcherType
		want           int
	}{
		{
			name:      "TestClassicMatch",
			header:    constant.AuthorizationHeader,
			match:     constant.AuthorizationType + "*",
			matchType: gmiddleware.RouteHeadersClassicMatcher,
			requestHeaders: map[string]string{
				"Authorization": "Bearer whatever",
				"Other":         "bera",
			},
			want: http.StatusForbidden,
		},
		{
			name:      "TestContainsMatch",
			header:    "Cookie",
			match:     "kc-access=",
			matchType: gmiddleware.RouteHeadersContainsMatcher,
			requestHeaders: map[string]string{
				"Cookie": "some-cookie=tadadada; kc-access=mytoken",
			},
			want: http.StatusForbidden,
		},
		{
			name:      "TestRegexMatch",
			header:    "X-Custom-Header",
			match:     ".*mycustom[4-9]+.*",
			matchType: gmiddleware.RouteHeadersRegexMatcher,
			requestHeaders: map[string]string{
				"X-Custom-Header": "test1mycustom564other",
			},
			want: http.StatusForbidden,
		},
		{
			name:      "TestMatchAndValueIsLowered",
			header:    constant.AuthorizationHeader,
			match:     constant.AuthorizationType + " *",
			matchType: gmiddleware.RouteHeadersClassicMatcher,
			requestHeaders: map[string]string{
				"Authorization": "bearer whatever",
			},
			want: http.StatusForbidden,
		},
		{
			name:      "TestNotMatch",
			header:    constant.AuthorizationHeader,
			match:     constant.AuthorizationType,
			matchType: gmiddleware.RouteHeadersClassicMatcher,
			requestHeaders: map[string]string{
				"Authorization": "Basic test",
			},
			want: http.StatusOK,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()

			headerRouterMiddleware := gmiddleware.RouteHeaders().
				SetMatchingType(test.matchType).
				Route(
					test.header,
					test.match,
					RouteHeadersDenyTestMiddleware(),
				).
				Handler

			router := chi.NewRouter()
			router.Use(headerRouterMiddleware)
			router.Get("/", func(_ http.ResponseWriter, _ *http.Request) {})

			var body []byte

			req := httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(body))
			for hName, hVal := range test.requestHeaders {
				req.Header.Set(hName, hVal)
			}

			router.ServeHTTP(recorder, req)
			res := recorder.Result()

			res.Body.Close()

			if res.StatusCode != test.want {
				t.Errorf("response is incorrect, got %d, want %d", recorder.Code, test.want)
			}
		})
	}
}
