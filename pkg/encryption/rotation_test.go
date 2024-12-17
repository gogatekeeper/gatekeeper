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

package encryption

import (
	"crypto/tls"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const (
	testCertificateFile = "../../tests/proxy.pem"
	testPrivateKeyFile  = "../../tests/proxy-key.pem"
)

func newTestCertificateRotator(t *testing.T) *CertificationRotation {
	t.Helper()
	counter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "proxy_certificate_rotation_total",
			Help: "The total amount of times the certificate has been rotated",
		},
	)
	rotation, err := NewCertificateRotator(testCertificateFile, testPrivateKeyFile, zap.NewNop(), &counter)
	assert.NotNil(t, rotation)
	assert.Equal(t, testCertificateFile, rotation.certificateFile)
	assert.Equal(t, testPrivateKeyFile, rotation.privateKeyFile)
	require.NoError(t, err, "unable to create the certificate rotator")

	return rotation
}

func TestNewCeritifacteRotator(t *testing.T) {
	counter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "proxy_certificate_rotation_total",
			Help: "The total amount of times the certificate has been rotated",
		},
	)
	c, err := NewCertificateRotator(testCertificateFile, testPrivateKeyFile, zap.NewNop(), &counter)
	assert.NotNil(t, c)
	require.NoError(t, err)
}

func TestNewCeritifacteRotatorFailure(t *testing.T) {
	counter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "proxy_certificate_rotation_total",
			Help: "The total amount of times the certificate has been rotated",
		},
	)
	c, err := NewCertificateRotator("./tests/does_not_exist", testPrivateKeyFile, zap.NewNop(), &counter)
	assert.Nil(t, c)
	require.Error(t, err)
}

func TestGetCertificate(t *testing.T) {
	c := newTestCertificateRotator(t)
	assert.NotEmpty(t, c.certificate)
	crt, err := c.GetCertificate(nil)
	require.NoError(t, err)
	assert.NotEmpty(t, crt)
}

func TestLoadCertificate(t *testing.T) {
	c := newTestCertificateRotator(t)
	assert.NotEmpty(t, c.certificate)
	_ = c.storeCertificate(tls.Certificate{})
	crt, err := c.GetCertificate(nil)
	require.NoError(t, err)
	assert.Equal(t, &tls.Certificate{}, crt)
}

func TestWatchCertificate(t *testing.T) {
	c := newTestCertificateRotator(t)
	err := c.Watch()
	require.NoError(t, err)
}
