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
	"fmt"
	"path"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type CertificationRotation struct {
	sync.RWMutex
	// certificate holds the current issuing certificate
	certificate tls.Certificate
	// certificateFile is the path the certificate
	certificateFile string
	// the privateKeyFile is the path of the private key
	privateKeyFile string
	// the logger for this service
	log            *zap.Logger
	rotationMetric *prometheus.Counter
}

// newCertificateRotator creates a new certificate.
func NewCertificateRotator(
	cert,
	key string,
	log *zap.Logger,
	metric *prometheus.Counter,
) (*CertificationRotation, error) {
	// step: attempt to load the certificate
	certificate, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	// @step: are we watching the files for changes?
	return &CertificationRotation{
		certificate:     certificate,
		certificateFile: cert,
		log:             log,
		privateKeyFile:  key,
		rotationMetric:  metric,
	}, nil
}

// watch is responsible for adding a file notification and watch on the files for changes.
func (c *CertificationRotation) Watch() error {
	c.log.Info(
		"adding a file watch on the certificates, certificate",
		zap.String("certificate", c.certificateFile),
		zap.String("private_key", c.privateKeyFile),
	)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	// add the files to the watch list
	for _, x := range []string{c.certificateFile, c.privateKeyFile} {
		if err := watcher.Add(path.Dir(x)); err != nil {
			return fmt.Errorf("unable to add watch on directory: %s, error: %w", path.Dir(x), err)
		}
	}

	// step: watching for events
	filewatchPaths := []string{c.certificateFile, c.privateKeyFile}

	go func() {
		c.log.Info("starting to watch changes to the tls certificate files")
		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Write == fsnotify.Write {
					// step: does the change effect our files?
					if !utils.ContainedIn(event.Name, filewatchPaths) {
						continue
					}
					// step: reload the certificate
					certificate, err := tls.LoadX509KeyPair(c.certificateFile, c.privateKeyFile)
					if err != nil {
						c.log.Error("unable to load the updated certificate",
							zap.String("filename", event.Name),
							zap.Error(err))
					}
					// @metric inform of the rotation
					(*c.rotationMetric).Inc()
					// step: load the new certificate
					_ = c.StoreCertificate(certificate)
					// step: print a debug message for us
					c.log.Info("replacing the server certifacte with updated version")
				}
			case err := <-watcher.Errors:
				c.log.Error("received an error from the file watcher", zap.Error(err))
			}
		}
	}()

	return nil
}

// StoreCertificate provides entrypoint to update the certificate.
func (c *CertificationRotation) StoreCertificate(certifacte tls.Certificate) error {
	c.Lock()
	defer c.Unlock()
	c.certificate = certifacte

	return nil
}

// GetCertificate is responsible for retrieving.
func (c *CertificationRotation) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.RLock()
	defer c.RUnlock()

	return &c.certificate, nil
}
