package e2e_test

import (
	"context"
	"math/rand"
	"os"
	"strconv"

	testsuite_test "github.com/gogatekeeper/gatekeeper/pkg/testsuite"
	ginkgo "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega" //nolint:revive //we want to use it for gomega
)

//nolint:gosec
var tlsCertificate = os.TempDir() + testsuite_test.FakeCertFilePrefix + strconv.Itoa(rand.Intn(10000))

//nolint:gosec
var tlsPrivateKey = os.TempDir() + testsuite_test.FakePrivFilePrefix + strconv.Itoa(rand.Intn(10000))

//nolint:gosec
var tlsCaCertificate = os.TempDir() + testsuite_test.FakeCaFilePrefix + strconv.Itoa(rand.Intn(10000))

var _ = ginkgo.BeforeSuite(func(_ context.Context) {
	fakeCertByte := []byte(testsuite_test.FakeCert)
	err := os.WriteFile(tlsCertificate, fakeCertByte, 0o600)
	Expect(err).NotTo(HaveOccurred())

	fakeKeyByte := []byte(testsuite_test.FakePrivateKey)
	err = os.WriteFile(tlsPrivateKey, fakeKeyByte, 0o600)
	Expect(err).NotTo(HaveOccurred())

	fakeCAByte := []byte(testsuite_test.FakeCA)
	err = os.WriteFile(tlsCaCertificate, fakeCAByte, 0o600)
	Expect(err).NotTo(HaveOccurred())
})

var _ = ginkgo.AfterSuite(func() {
	defer os.Remove(tlsCertificate)
	defer os.Remove(tlsPrivateKey)
	defer os.Remove(tlsCaCertificate)
})
