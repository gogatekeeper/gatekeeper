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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	yaml "gopkg.in/yaml.v2"
)

// newDefaultConfig returns a initialized config
func newDefaultConfig() *Config {
	var hostnames []string
	if name, err := os.Hostname(); err == nil {
		hostnames = append(hostnames, name)
	}
	hostnames = append(hostnames, []string{"localhost", "127.0.0.1", "::1"}...)

	return &Config{
		AccessTokenDuration:           time.Duration(720) * time.Hour,
		CookieAccessName:              constant.AccessCookie,
		CookieRefreshName:             constant.RefreshCookie,
		CookieOAuthStateName:          constant.RequestStateCookie,
		CookieRequestURIName:          constant.RequestURICookie,
		EnableAuthorizationCookies:    true,
		EnableAuthorizationHeader:     true,
		EnableDefaultDeny:             true,
		EnableSessionCookies:          true,
		EnableTokenHeader:             true,
		HTTPOnlyCookie:                true,
		Headers:                       make(map[string]string),
		LetsEncryptCacheDir:           "./cache/",
		MatchClaims:                   make(map[string]string),
		MaxIdleConns:                  100,
		MaxIdleConnsPerHost:           50,
		OAuthURI:                      "/oauth",
		OpenIDProviderTimeout:         30 * time.Second,
		PreserveHost:                  false,
		SelfSignedTLSExpiration:       3 * time.Hour,
		SelfSignedTLSHostnames:        hostnames,
		RequestIDHeader:               "X-Request-ID",
		ResponseHeaders:               make(map[string]string),
		SameSiteCookie:                constant.SameSiteLax,
		Scopes:                        []string{"email", "profile"},
		SecureCookie:                  true,
		ServerIdleTimeout:             120 * time.Second,
		ServerReadTimeout:             10 * time.Second,
		ServerWriteTimeout:            10 * time.Second,
		SkipOpenIDProviderTLSVerify:   false,
		SkipUpstreamTLSVerify:         true,
		Tags:                          make(map[string]string),
		TLSMinVersion:                 "tlsv1.3",
		UpstreamExpectContinueTimeout: 10 * time.Second,
		UpstreamKeepaliveTimeout:      10 * time.Second,
		UpstreamKeepalives:            true,
		UpstreamResponseHeaderTimeout: 10 * time.Second,
		UpstreamTLSHandshakeTimeout:   10 * time.Second,
		UpstreamTimeout:               10 * time.Second,
		UseLetsEncrypt:                false,
		ForwardingGrantType:           GrantTypeUserCreds,
		PatRetryCount:                 5,
		PatRetryInterval:              10 * time.Second,
		OpaTimeout:                    10 * time.Second,
	}
}

// readConfigFile reads and parses the configuration file
func ReadConfigFile(filename string, config *Config) error {
	content, err := ioutil.ReadFile(filename)

	if err != nil {
		return err
	}
	// step: attempt to un-marshal the data
	switch ext := filepath.Ext(filename); ext {
	case "json":
		err = json.Unmarshal(content, config)
	default:
		err = yaml.Unmarshal(content, config)
	}

	return err
}

func writeFakeConfigFile(t *testing.T, content string) *os.File {
	file, err := ioutil.TempFile("", "node_label_file")
	if err != nil {
		t.Fatalf("unexpected error creating node_label_file: %v", err)
	}
	file.Close()

	if err := ioutil.WriteFile(file.Name(), []byte(content), 0600); err != nil {
		t.Fatalf("unexpected error writing node label file: %v", err)
	}

	return file
}

// WithOAuthURI returns the oauth uri
func (r *Config) WithOAuthURI(uri string) string {
	if r.BaseURI != "" {
		return fmt.Sprintf("%s/%s/%s", r.BaseURI, r.OAuthURI, uri)
	}

	return fmt.Sprintf("%s/%s", r.OAuthURI, uri)
}

func (r *Config) update() error {
	updateRegistry := []func() error{
		r.updateDiscoveryURI,
		r.updateRealm,
	}

	for _, updateFunc := range updateRegistry {
		if err := updateFunc(); err != nil {
			return err
		}
	}

	return nil
}

// isValid validates if the config is valid
func (r *Config) isValid() error {
	if r.ListenAdmin == r.Listen {
		r.ListenAdmin = ""
	}

	if r.ListenAdminScheme == "" {
		r.ListenAdminScheme = constant.SecureScheme
	}

	validationRegistry := []func() error{
		r.isListenValid,
		r.isListenAdminSchemeValid,
		r.isOpenIDProviderProxyValid,
		r.isMaxIdlleConnValid,
		r.isSameSiteValid,
		r.isTLSFilesValid,
		r.isAdminTLSFilesValid,
		r.isLetsEncryptValid,
		r.isTLSMinValid,
		r.isForwardingProxySettingsValid,
		r.isReverseProxySettingsValid,
	}

	for _, validationFunc := range validationRegistry {
		if err := validationFunc(); err != nil {
			return err
		}
	}

	return nil
}

// hasCustomSignInPage checks if there is a custom sign in  page
func (r *Config) hasCustomSignInPage() bool {
	return r.SignInPage != ""
}

// hasForbiddenPage checks if there is a custom forbidden page
func (r *Config) hasCustomForbiddenPage() bool {
	return r.ForbiddenPage != ""
}

// hasCustomErrorPage checks if there is a custom error page
func (r *Config) hasCustomErrorPage() bool {
	return r.ErrorPage != ""
}

func (r *Config) isListenValid() error {
	if r.Listen == "" {
		return errors.New("you have not specified the listening interface")
	}
	return nil
}

func (r *Config) isListenAdminSchemeValid() error {
	if r.ListenAdminScheme != constant.SecureScheme &&
		r.ListenAdminScheme != constant.UnsecureScheme {
		return errors.New("scheme for admin listener must be one of [http, https]")
	}
	return nil
}

func (r *Config) isOpenIDProviderProxyValid() error {
	if r.OpenIDProviderProxy != "" {
		_, err := url.ParseRequestURI(r.OpenIDProviderProxy)

		if err != nil {
			return errors.New("invalid proxy address for open IDP provider proxy")
		}
	}

	return nil
}

func (r *Config) isMaxIdlleConnValid() error {
	if r.MaxIdleConns <= 0 {
		return errors.New("max-idle-connections must be a number > 0")
	}

	if r.MaxIdleConnsPerHost < 0 || r.MaxIdleConnsPerHost > r.MaxIdleConns {
		return errors.New(
			"maxi-idle-connections-per-host must be a " +
				"number > 0 and <= max-idle-connections",
		)
	}
	return nil
}

func (r *Config) isSameSiteValid() error {
	if r.SameSiteCookie != "" && r.SameSiteCookie != constant.SameSiteStrict &&
		r.SameSiteCookie != constant.SameSiteLax && r.SameSiteCookie != constant.SameSiteNone {
		return errors.New("same-site-cookie must be one of Strict|Lax|None")
	}
	return nil
}

//nolint:cyclop
func (r *Config) isTLSFilesValid() error {
	if r.TLSCertificate != "" && r.TLSPrivateKey == "" {
		return errors.New("you have not provided a private key")
	}

	if r.TLSPrivateKey != "" && r.TLSCertificate == "" {
		return errors.New("you have not provided a certificate file")
	}

	if r.TLSCertificate != "" && !utils.FileExists(r.TLSCertificate) {
		return fmt.Errorf("the tls certificate %s does not exist", r.TLSCertificate)
	}

	if r.TLSPrivateKey != "" && !utils.FileExists(r.TLSPrivateKey) {
		return fmt.Errorf("the tls private key %s does not exist", r.TLSPrivateKey)
	}

	if r.TLSCaCertificate != "" && !utils.FileExists(r.TLSCaCertificate) {
		return fmt.Errorf(
			"the tls ca certificate file %s does not exist",
			r.TLSCaCertificate,
		)
	}

	if r.TLSClientCertificate != "" && !utils.FileExists(r.TLSClientCertificate) {
		return fmt.Errorf(
			"the tls client certificate %s does not exist",
			r.TLSClientCertificate,
		)
	}

	return nil
}

//nolint:cyclop
func (r *Config) isAdminTLSFilesValid() error {
	if r.TLSAdminCertificate != "" && r.TLSAdminPrivateKey == "" {
		return errors.New("you have not provided a private key for admin endpoint")
	}

	if r.TLSAdminPrivateKey != "" && r.TLSAdminCertificate == "" {
		return errors.New(
			"you have not provided a certificate file for admin endpoint",
		)
	}

	if r.TLSAdminCertificate != "" && !utils.FileExists(r.TLSAdminCertificate) {
		return fmt.Errorf(
			"the tls certificate %s does not exist for admin endpoint",
			r.TLSAdminCertificate,
		)
	}

	if r.TLSAdminPrivateKey != "" && !utils.FileExists(r.TLSAdminPrivateKey) {
		return fmt.Errorf(
			"the tls private key %s does not exist for admin endpoint",
			r.TLSAdminPrivateKey,
		)
	}

	if r.TLSAdminCaCertificate != "" && !utils.FileExists(r.TLSAdminCaCertificate) {
		return fmt.Errorf(
			"the tls ca certificate file %s does not exist for admin endpoint",
			r.TLSAdminCaCertificate,
		)
	}

	if r.TLSAdminClientCertificate != "" && !utils.FileExists(r.TLSAdminClientCertificate) {
		return fmt.Errorf(
			"the tls client certificate %s does not exist for admin endpoint",
			r.TLSAdminClientCertificate,
		)
	}

	return nil
}

func (r *Config) isLetsEncryptValid() error {
	if r.UseLetsEncrypt && r.LetsEncryptCacheDir == "" {
		return fmt.Errorf("the letsencrypt cache dir has not been set")
	}
	return nil
}

func (r *Config) isTLSMinValid() error {
	switch strings.ToLower(r.TLSMinVersion) {
	case "":
		return fmt.Errorf("minimal TLS version should not be empty")
	//nolint: goconst
	case "tlsv1.0":
	//nolint: goconst
	case "tlsv1.1":
	//nolint: goconst
	case "tlsv1.2":
	//nolint: goconst
	case "tlsv1.3":
	default:
		return fmt.Errorf("invalid minimal TLS version specified")
	}
	return nil
}

func (r *Config) isForwardingProxySettingsValid() error {
	if r.EnableForwarding {
		validationRegistry := []func() error{
			r.isClientIDValid,
			r.isDiscoveryURLValid,
			r.isForwardingGrantValid,
			func() error {
				if r.TLSCertificate != "" {
					return errors.New("you don't need to specify a " +
						"tls-certificate, use tls-ca-certificate instead",
					)
				}
				return nil
			},
			func() error {
				if r.TLSPrivateKey != "" {
					return errors.New("you don't need to specify the " +
						"tls-private-key, use tls-ca-key instead",
					)
				}
				return nil
			},
		}

		for _, validationFunc := range validationRegistry {
			if err := validationFunc(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *Config) isReverseProxySettingsValid() error {
	if !r.EnableForwarding {
		validationRegistry := []func() error{
			r.isNoProxyValid,
			r.isUpstreamValid,
			r.isDefaultDenyValid,
			r.isExternalAuthzValid,
			r.isTokenVerificationSettingsValid,
			r.isResourceValid,
			r.isMatchClaimValid,
		}

		for _, validationFunc := range validationRegistry {
			if err := validationFunc(); err != nil {
				return err
			}
		}

		return nil
	}

	return nil
}

func (r *Config) isTokenVerificationSettingsValid() error {
	// step: if the skip verification is off, we need the below
	if !r.SkipTokenVerification {
		validationRegistry := []func() error{
			r.isClientIDValid,
			r.isDiscoveryURLValid,
			func() error {
				r.RedirectionURL = strings.TrimSuffix(r.RedirectionURL, "/")
				return nil
			},
			r.isSecurityFilterValid,
			r.isTokenEncryptionValid,
			r.isSecureCookieValid,
			r.isStoreURLValid,
		}

		for _, validationFunc := range validationRegistry {
			if err := validationFunc(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *Config) isNoProxyValid() error {
	if r.NoProxy && !r.NoRedirects {
		return errors.New("noproxy option must be used with noredirects")
	}
	return nil
}

func (r *Config) isUpstreamValid() error {
	if r.Upstream == "" && !r.NoProxy {
		return errors.New("you have not specified an upstream endpoint to proxy to")
	}

	if !r.NoProxy {
		if _, err := url.ParseRequestURI(r.Upstream); err != nil {
			return fmt.Errorf("the upstream endpoint is invalid, %s", err)
		}
	}

	if r.SkipUpstreamTLSVerify && r.UpstreamCA != "" {
		return fmt.Errorf("you cannot skip upstream tls and load a root ca: %s to verify it", r.UpstreamCA)
	}

	return nil
}

func (r *Config) isClientIDValid() error {
	if r.ClientID == "" {
		return errors.New("you have not specified the client id")
	}
	return nil
}

func (r *Config) isDiscoveryURLValid() error {
	if r.DiscoveryURL == "" {
		return errors.New("you have not specified the discovery url")
	}
	return nil
}

func (r *Config) isForwardingGrantValid() error {
	if r.ForwardingGrantType == GrantTypeUserCreds {
		if r.ForwardingUsername == "" {
			return errors.New("no forwarding username")
		}

		if r.ForwardingPassword == "" {
			return errors.New("no forwarding password")
		}
	}

	if r.ForwardingGrantType == GrantTypeClientCreds {
		if r.ClientSecret == "" {
			return errors.New("you have not specified the client secret")
		}
	}

	return nil
}

func (r *Config) isSecurityFilterValid() error {
	if !r.EnableSecurityFilter {
		if r.EnableHTTPSRedirect {
			return errors.New(
				"the security filter must be switch on for this feature: http-redirect",
			)
		}

		if r.EnableBrowserXSSFilter {
			return errors.New(
				"the security filter must be switch on " +
					"for this feature: brower-xss-filter",
			)
		}

		if r.EnableFrameDeny {
			return errors.New(
				"the security filter must be switch on " +
					"for this feature: frame-deny-filter",
			)
		}

		if r.ContentSecurityPolicy != "" {
			return errors.New(
				"the security filter must be switch on " +
					"for this feature: content-security-policy",
			)
		}

		if len(r.Hostnames) > 0 {
			return errors.New(
				"the security filter must be switch on for this feature: hostnames",
			)
		}
	}

	return nil
}

func (r *Config) isTokenEncryptionValid() error {
	if (r.EnableEncryptedToken || r.ForceEncryptedCookie) &&
		r.EncryptionKey == "" {
		return errors.New(
			"you have not specified an encryption key for encoding the access token",
		)
	}

	if r.EnableRefreshTokens && r.EncryptionKey == "" {
		return errors.New(
			"you have not specified an encryption key for encoding the session state",
		)
	}

	if r.EnableRefreshTokens && (len(r.EncryptionKey) != 16 &&
		len(r.EncryptionKey) != 32) {
		return fmt.Errorf(
			"the encryption key (%d) must be either 16 or 32 "+
				"characters for AES-128/AES-256 selection",
			len(r.EncryptionKey),
		)
	}

	return nil
}

func (r *Config) isSecureCookieValid() error {
	if !r.NoRedirects && r.SecureCookie && r.RedirectionURL != "" &&
		!strings.HasPrefix(r.RedirectionURL, "https") {
		return errors.New(
			"the cookie is set to secure but your redirection url is non-tls",
		)
	}

	return nil
}

func (r *Config) isStoreURLValid() error {
	if r.StoreURL != "" {
		if _, err := url.ParseRequestURI(r.StoreURL); err != nil {
			return fmt.Errorf("the store url is invalid, error: %s", err)
		}
	}

	return nil
}

func (r *Config) isResourceValid() error {
	// step: add custom http methods for check
	if r.CustomHTTPMethods != nil {
		for _, customHTTPMethod := range r.CustomHTTPMethods {
			chi.RegisterMethod(customHTTPMethod)
			utils.AllHTTPMethods = append(utils.AllHTTPMethods, customHTTPMethod)
		}
	}

	// check: ensure each of the resource are valid
	for _, resource := range r.Resources {
		if err := resource.Valid(); err != nil {
			return err
		}

		if resource.URL == allPath && (r.EnableDefaultDeny || r.EnableDefaultDenyStrict) {
			switch resource.WhiteListed {
			case true:
				return apperrors.ErrDefaultDenyWhitelistConflict
			default:
				return apperrors.ErrDefaultDenyUserDefinedConflict
			}
		}
	}

	return nil
}

func (r *Config) isMatchClaimValid() error {
	// step: validate the claims are validate regex's
	for k, claim := range r.MatchClaims {
		if _, err := regexp.Compile(claim); err != nil {
			return fmt.Errorf(
				"the claim matcher: %s for claim: %s is not a valid regex",
				claim,
				k,
			)
		}
	}

	return nil
}

func (r *Config) isExternalAuthzValid() error {
	if r.EnableUma && r.EnableOpa {
		return errors.New(
			"only one type of external authz can be enabled at once",
		)
	}

	if r.EnableUma {
		if r.ClientID == "" || r.ClientSecret == "" {
			return errors.New(
				"enable uma requires client credentials",
			)
		}
		if !r.NoRedirects {
			return errors.New(
				"enable-uma requires no-redirects option",
			)
		}
	} else if r.EnableOpa {
		authzURL, err := url.ParseRequestURI(r.OpaAuthzURI)

		if err != nil {
			return fmt.Errorf("not valid OPA authz URL, %w", err)
		}

		r.OpaAuthzURL = authzURL
	}

	return nil
}

func (r *Config) isDefaultDenyValid() error {
	if r.EnableDefaultDeny && r.EnableDefaultDenyStrict {
		return errors.New(
			"only one of enable-default-deny/enable-default-deny-strict can be true",
		)
	}
	return nil
}

func (r *Config) updateDiscoveryURI() error {
	// step: fix up the url if required, the underlining lib will add
	// the .well-known/openid-configuration to the discovery url for us.
	r.DiscoveryURL = strings.TrimSuffix(
		r.DiscoveryURL,
		"/.well-known/openid-configuration",
	)

	uri, err := url.ParseRequestURI(r.DiscoveryURL)

	if err != nil {
		return fmt.Errorf(
			"failed to parse discovery url: %w",
			err,
		)
	}

	r.DiscoveryURI = uri

	return nil
}

func (r *Config) updateRealm() error {
	path := strings.Split(r.DiscoveryURI.Path, "/")

	if len(path) != 4 {
		return fmt.Errorf("missing realm in discovery url?")
	}

	realm := path[len(path)-1]
	r.Realm = realm
	return nil
}
