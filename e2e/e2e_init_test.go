package e2e_test

import (
	"context"
	"crypto/x509"
	"math/rand"
	"os"
	"strconv"

	testsuite_test "github.com/gogatekeeper/gatekeeper/pkg/testsuite"
	ginkgo "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega" //nolint:revive //we want to use it for gomega
)

//nolint:gosec, gochecknoglobals
var tlsCertificate = os.TempDir() + testsuite_test.FakeCertFilePrefix + strconv.Itoa(rand.Intn(10000))

//nolint:gosec, gochecknoglobals
var tlsPrivateKey = os.TempDir() + testsuite_test.FakePrivFilePrefix + strconv.Itoa(rand.Intn(10000))

//nolint:gosec, gochecknoglobals
var tlsCaCertificate = os.TempDir() + testsuite_test.FakeCaFilePrefix + strconv.Itoa(rand.Intn(10000))

//nolint:gosec, gochecknoglobals
var tlsCaKey = os.TempDir() + testsuite_test.FakeCaKeyFilePrefix + strconv.Itoa(rand.Intn(10000))

//nolint:gochecknoglobals
var caPool *x509.CertPool

var _ = ginkgo.BeforeSuite(func(_ context.Context) {
	caPool = x509.NewCertPool()
	caPool.AppendCertsFromPEM([]byte(fakeCA))

	fakeCertByte := []byte(fakeCert)
	err := os.WriteFile(tlsCertificate, fakeCertByte, 0o600)
	Expect(err).NotTo(HaveOccurred())

	fakeKeyByte := []byte(fakePrivateKey)
	err = os.WriteFile(tlsPrivateKey, fakeKeyByte, 0o600)
	Expect(err).NotTo(HaveOccurred())

	fakeCAByte := []byte(fakeCA)
	err = os.WriteFile(tlsCaCertificate, fakeCAByte, 0o600)
	Expect(err).NotTo(HaveOccurred())

	fakeCAKeyByte := []byte(fakeCAKey)
	err = os.WriteFile(tlsCaKey, fakeCAKeyByte, 0o600)
	Expect(err).NotTo(HaveOccurred())
})

var _ = ginkgo.AfterSuite(func() {
	defer os.Remove(tlsCertificate)
	defer os.Remove(tlsPrivateKey)
	defer os.Remove(tlsCaCertificate)
})
