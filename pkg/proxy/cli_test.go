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

//nolint:testpackage
package proxy

import (
	"testing"

	"github.com/gogatekeeper/gatekeeper/pkg/config"
	keycloakcore "github.com/gogatekeeper/gatekeeper/pkg/keycloak/proxy/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func TestNewOauthProxyApp(t *testing.T) {
	a := NewOauthProxyApp(keycloakcore.Provider)
	assert.NotNil(t, a)
}

func TestGetCLIOptions(t *testing.T) {
	cfg := config.ProduceConfig(keycloakcore.Provider)
	if flags := getCommandLineOptions(cfg); flags == nil {
		t.Error("we should have received some flags options")
	}
}

func TestReadOptions(t *testing.T) {
	capp := cli.NewApp()
	cfg := config.ProduceConfig(keycloakcore.Provider)
	capp.Flags = getCommandLineOptions(cfg)
	capp.Action = func(cx *cli.Context) error {
		ero := parseCLIOptions(cx, cfg)
		require.NoError(t, ero)
		return nil
	}
	err := capp.Run([]string{""})
	require.NoError(t, err)
}
