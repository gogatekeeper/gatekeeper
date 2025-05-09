//go:build !e2e
// +build !e2e

/*
Copyright 2018 All rights reserved.

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

package encryption_test

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewSelfSignedCertificate(t *testing.T) {
	c, err := encryption.NewSelfSignedCertificate([]string{"localhost"}, 5*time.Minute, zap.NewNop())
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func TestSelfSignedNoHostnames(t *testing.T) {
	c, err := encryption.NewSelfSignedCertificate([]string{}, 5*time.Minute, zap.NewNop())
	require.Error(t, err)
	assert.Nil(t, c)
}

func TestSelfSignedExpirationBad(t *testing.T) {
	c, err := encryption.NewSelfSignedCertificate([]string{"localhost"}, 1*time.Minute, zap.NewNop())
	require.Error(t, err)
	assert.Nil(t, c)
}

func TestSelfSignedGetCertificate(t *testing.T) {
	c, err := encryption.NewSelfSignedCertificate([]string{"localhost"}, 5*time.Minute, zap.NewNop())
	require.NoError(t, err)
	require.NotNil(t, c)
	cert, err := c.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	assert.NotNil(t, cert)
}
