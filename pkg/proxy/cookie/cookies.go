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

package cookie

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	uuid "github.com/gofrs/uuid"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
)

type Manager struct {
	CookieDomain         string
	BaseURI              string
	SameSiteCookie       string
	CookieAccessName     string
	CookieRefreshName    string
	CookieIDTokenName    string
	CookiePKCEName       string
	CookieUMAName        string
	CookieRequestURIName string
	CookieOAuthStateName string
	HTTPOnlyCookie       bool
	SecureCookie         bool
	EnableSessionCookies bool
	NoProxy              bool
	NoRedirects          bool
}

// DropCookie drops a cookie into the response
func (cm *Manager) DropCookie(
	wrt http.ResponseWriter,
	name,
	value string,
	duration time.Duration,
) {
	// step: default to the host header, else the config domain
	domain := ""
	if cm.CookieDomain != "" {
		domain = cm.CookieDomain
	}

	path := cm.BaseURI
	if path == "" {
		path = "/"
	}

	cookie := &http.Cookie{
		Domain:   domain,
		HttpOnly: cm.HTTPOnlyCookie,
		Name:     name,
		Path:     path,
		Secure:   cm.SecureCookie,
		Value:    value,
	}

	if !cm.EnableSessionCookies && duration != 0 || duration == constant.InvalidCookieDuration {
		cookie.Expires = time.Now().Add(duration)
	}

	switch cm.SameSiteCookie {
	case constant.SameSiteStrict:
		cookie.SameSite = http.SameSiteStrictMode
	case constant.SameSiteLax:
		cookie.SameSite = http.SameSiteLaxMode
	case constant.SameSiteNone:
		cookie.SameSite = http.SameSiteNoneMode
	}

	http.SetCookie(wrt, cookie)
}

// maxCookieChunkSize calculates max cookie chunk size, which can be used for cookie value
// this seems to be not useful as many browsers have limits of all cookies per domain = 4096 bytes
func (cm *Manager) GetMaxCookieChunkLength(
	req *http.Request,
	cookieName string,
) int {
	maxCookieChunkLength := constant.CookiesPerDomainSize - len(cookieName)

	if cm.CookieDomain != "" {
		maxCookieChunkLength -= len(cm.CookieDomain)
	} else {
		maxCookieChunkLength -= len(strings.Split(req.Host, ":")[0])
	}

	if cm.HTTPOnlyCookie {
		maxCookieChunkLength -= len("HttpOnly; ")
	}

	if !cm.EnableSessionCookies {
		maxCookieChunkLength -= len("Expires=Mon, 02 Jan 2006 03:04:05 MST; ")
	}

	switch cm.SameSiteCookie {
	case constant.SameSiteStrict:
		maxCookieChunkLength -= len("SameSite=Strict ")
	case constant.SameSiteLax:
		maxCookieChunkLength -= len("SameSite=Lax ")
	case constant.SameSiteNone:
		maxCookieChunkLength -= len("SameSite=None ")
	}

	if cm.SecureCookie {
		maxCookieChunkLength -= len("Secure")
	}

	return maxCookieChunkLength
}

// dropCookieWithChunks drops a cookie from the response, taking into account possible chunks
func (cm *Manager) dropCookieWithChunks(
	req *http.Request,
	wrt http.ResponseWriter,
	name,
	value string,
	duration time.Duration,
) {
	maxCookieChunkLength := cm.GetMaxCookieChunkLength(req, name)

	if len(value) <= maxCookieChunkLength {
		cm.DropCookie(wrt, name, value, duration)
	} else {
		// write divided cookies because payload is too long for single cookie
		cm.DropCookie(wrt, name, value[0:maxCookieChunkLength], duration)

		for idx := maxCookieChunkLength; idx < len(value); idx += maxCookieChunkLength {
			end := idx + maxCookieChunkLength
			if end > len(value) {
				end = len(value)
			}

			cm.DropCookie(
				wrt,
				name+"-"+strconv.Itoa(idx/maxCookieChunkLength),
				value[idx:end],
				duration,
			)
		}
	}
}

// dropAccessTokenCookie drops a access token cookie
func (cm *Manager) DropAccessTokenCookie(req *http.Request, w http.ResponseWriter, value string, duration time.Duration) {
	cm.dropCookieWithChunks(req, w, cm.CookieAccessName, value, duration)
}

// DropRefreshTokenCookie drops a refresh token cookie
func (cm *Manager) DropRefreshTokenCookie(req *http.Request, w http.ResponseWriter, value string, duration time.Duration) {
	cm.dropCookieWithChunks(req, w, cm.CookieRefreshName, value, duration)
}

// dropIdTokenCookie drops a id token cookie
func (cm *Manager) DropIDTokenCookie(req *http.Request, w http.ResponseWriter, value string, duration time.Duration) {
	cm.dropCookieWithChunks(req, w, cm.CookieIDTokenName, value, duration)
}

// dropUMATokenCookie drops a uma token cookie
func (cm *Manager) DropUMATokenCookie(req *http.Request, w http.ResponseWriter, value string, duration time.Duration) {
	cm.dropCookieWithChunks(req, w, cm.CookieUMAName, value, duration)
}

// DropStateParameterCookie sets a state parameter cookie into the response
func (cm *Manager) DropStateParameterCookie(req *http.Request, wrt http.ResponseWriter) string {
	uuid, err := uuid.NewV4()

	if err != nil {
		wrt.WriteHeader(http.StatusInternalServerError)
	}

	requestURI := req.URL.RequestURI()

	if cm.NoProxy && !cm.NoRedirects {
		xReqURI := req.Header.Get(constant.HeaderXForwardedURI)
		requestURI = xReqURI
	}

	encRequestURI := base64.StdEncoding.EncodeToString([]byte(requestURI))

	cm.DropCookie(wrt, cm.CookieRequestURIName, encRequestURI, 0)
	cm.DropCookie(wrt, cm.CookieOAuthStateName, uuid.String(), 0)

	return uuid.String()
}

// DropPKCECookie sets a code verifier cookie into the response
func (cm *Manager) DropPKCECookie(wrt http.ResponseWriter, codeVerifier string) {
	cm.DropCookie(wrt, cm.CookiePKCEName, codeVerifier, 0)
}

// ClearAllCookies is just a helper function for the below
func (cm *Manager) ClearAllCookies(req *http.Request, w http.ResponseWriter) {
	cm.ClearAccessTokenCookie(req, w)
	cm.ClearRefreshTokenCookie(req, w)
	cm.ClearIDTokenCookie(req, w)
	cm.ClearUMATokenCookie(req, w)
	cm.ClearStateParameterCookie(req, w)
}

func (cm *Manager) ClearCookie(req *http.Request, wrt http.ResponseWriter, name string) {
	cm.DropCookie(wrt, name, "", constant.InvalidCookieDuration)

	// clear divided cookies
	for idx := 1; idx < 600; idx++ {
		var _, err = req.Cookie(name + "-" + strconv.Itoa(idx))

		if err == nil {
			cm.DropCookie(
				wrt,
				name+"-"+strconv.Itoa(idx),
				"",
				constant.InvalidCookieDuration,
			)
		} else {
			break
		}
	}
}

// clearRefreshSessionCookie clears the session cookie
func (cm *Manager) ClearRefreshTokenCookie(req *http.Request, wrt http.ResponseWriter) {
	cm.ClearCookie(req, wrt, cm.CookieRefreshName)
}

// ClearAccessTokenCookie clears the session cookie
func (cm *Manager) ClearAccessTokenCookie(req *http.Request, wrt http.ResponseWriter) {
	cm.ClearCookie(req, wrt, cm.CookieAccessName)
}

// ClearIDTokenCookie clears the session cookie
func (cm *Manager) ClearIDTokenCookie(req *http.Request, wrt http.ResponseWriter) {
	cm.ClearCookie(req, wrt, cm.CookieIDTokenName)
}

// ClearUMATokenCookie clears the session cookie
func (cm *Manager) ClearUMATokenCookie(req *http.Request, wrt http.ResponseWriter) {
	cm.ClearCookie(req, wrt, cm.CookieUMAName)
}

// ClearPKCECookie clears the session cookie
func (cm *Manager) ClearPKCECookie(req *http.Request, wrt http.ResponseWriter) {
	cm.ClearCookie(req, wrt, cm.CookiePKCEName)
}

// ClearStateParameterCookie clears the session cookie
func (cm *Manager) ClearStateParameterCookie(req *http.Request, wrt http.ResponseWriter) {
	cm.ClearCookie(req, wrt, cm.CookieRequestURIName)
	cm.ClearCookie(req, wrt, cm.CookieOAuthStateName)
}

// findCookie looks for a cookie in a list of cookies
func FindCookie(name string, cookies []*http.Cookie) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}

	return nil
}

// filterCookies is responsible for censoring any cookies we don't want sent
func FilterCookies(req *http.Request, filter []string) error {
	// @NOTE: there doesn't appear to be a way of removing a cookie from the http.Request as
	// AddCookie() just append
	cookies := req.Cookies()
	// @step: empty the current cookies
	req.Header.Set("Cookie", "")
	// @step: iterate the cookies and filter out anything we
	for _, cookie := range cookies {
		var found bool
		// @step: does this cookie match our filter?
		for _, n := range filter {
			if strings.HasPrefix(cookie.Name, n) {
				req.AddCookie(&http.Cookie{Name: cookie.Name, Value: "censored"})
				found = true
				break
			}
		}

		if !found {
			req.AddCookie(cookie)
		}
	}

	return nil
}
