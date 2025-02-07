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

package encryption

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"go.uber.org/zap"
)

type SelfSignedCertificate struct {
	sync.RWMutex
	// certificate holds the current issuing certificate
	certificate tls.Certificate
	// expiration is the certificate expiration
	expiration time.Duration
	// hostnames is the list of host names on the certificate
	hostnames []string
	// privateKey is the rsa private key
	privateKey *ed25519.PrivateKey
	// the logger for this service
	log *zap.Logger
	// stopCh is a channel to close off the rotation
	cancel context.CancelFunc
}

// newSelfSignedCertificate creates and returns a self signed certificate manager.
func NewSelfSignedCertificate(
	hostnames []string,
	expiry time.Duration,
	log *zap.Logger,
) (*SelfSignedCertificate, error) {
	if len(hostnames) == 0 {
		return nil, apperrors.ErrCertSelfNoHostname
	}

	if expiry < 5*time.Minute {
		return nil, apperrors.ErrCertSelfLowExpiration
	}

	// @step: generate a certificate pair
	log.Info(
		"generating a private key for self-signed certificate",
		zap.String("common_name", hostnames[0]),
	)

	_, key, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		return nil, err
	}

	// @step: create an initial certificate
	certificate, err := CreateCertificate(&key, hostnames, expiry)

	if err != nil {
		return nil, err
	}

	// @step: create a context to run under
	ctx, cancel := context.WithCancel(context.Background())

	svc := &SelfSignedCertificate{
		certificate: certificate,
		expiration:  expiry,
		hostnames:   hostnames,
		log:         log,
		privateKey:  &key,
		cancel:      cancel,
	}

	if err := svc.rotate(ctx); err != nil {
		return nil, err
	}

	return svc, nil
}

// rotate is responsible for rotation the certificate.
func (c *SelfSignedCertificate) rotate(ctx context.Context) error {
	go func() {
		c.log.Info("starting the self-signed certificate rotation",
			zap.Duration("expiration", c.expiration))

		for {
			expires := time.Now().Add(c.expiration).Add(-5 * time.Minute)
			ticker := time.Until(expires)

			select {
			case <-ctx.Done():
				return
			case <-time.After(ticker):
			}
			c.log.Info(
				"going to sleep until required for rotation",
				zap.Time("expires", expires),
				zap.Duration("duration", time.Until(expires)),
			)

			// @step: got to sleep until we need to rotate
			time.Sleep(time.Until(expires))

			// @step: create a new certificate for us
			cert, _ := CreateCertificate(c.privateKey, c.hostnames, c.expiration)
			c.log.Info("updating the certificate for server")

			// @step: update the current certificate
			c.updateCertificate(cert)
		}
	}()

	return nil
}

// updateCertificate is responsible for update the certificate.
func (c *SelfSignedCertificate) updateCertificate(cert tls.Certificate) {
	c.Lock()
	defer c.Unlock()

	c.certificate = cert
}

// GetCertificate is responsible for retrieving.
func (c *SelfSignedCertificate) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.RLock()
	defer c.RUnlock()

	return &c.certificate, nil
}

// createCertificate is responsible for creating a certificate.
func CreateCertificate(key *ed25519.PrivateKey, hostnames []string, expire time.Duration) (tls.Certificate, error) {
	// @step: create a serial for the certificate
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), constant.SelfSignedMaxSerialBits))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotAfter:              time.Now().Add(expire),
		NotBefore:             time.Now().Add(-30 * time.Second),
		PublicKeyAlgorithm:    x509.Ed25519,
		SerialNumber:          serial,
		Subject: pkix.Name{
			CommonName:   hostnames[0],
			Organization: []string{"Gatekeeper"},
		},
	}

	// @step: add the hostnames to the certificate template
	if len(hostnames) > 1 {
		for _, x := range hostnames[1:] {
			if ip := net.ParseIP(x); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, x)
			}
		}
	}

	// @step: create the certificate
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}

	pkcsPrivKey, err := x509.MarshalPKCS8PrivateKey(*key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "X25519 PRIVATE KEY", Bytes: pkcsPrivKey})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// loadCA loads the certificate authority.
func LoadCA(cert, key string) (*tls.Certificate, error) {
	caCert, err := os.ReadFile(cert)

	if err != nil {
		return nil, err
	}

	caKey, err := os.ReadFile(key)

	if err != nil {
		return nil, err
	}

	cAuthority, err := tls.X509KeyPair(caCert, caKey)

	if err != nil {
		return nil, err
	}

	cAuthority.Leaf, err = x509.ParseCertificate(cAuthority.Certificate[0])

	return &cAuthority, err
}
