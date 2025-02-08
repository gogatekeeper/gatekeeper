package encryption_test

import (
	"bytes"
	"testing"

	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//nolint:gochecknoglobals
var (
	fakePlainText = []byte(`nFlhnhwRzC9uJ9mjhR0PQezUpIiDlU9ASLqH1KIKFhBZZrMZfnAAdHdgKs2OJoni8cTSQ
	JxkaNpboZ6hnrMytlw5kf0biF7dLTU885uHIGkUIRy75hx6BaTEEhbN36qVTxediEHd6xeBPS3qpJ7riO6J
	EeaQr1rroDL0LvmDyB6Zds4LdVQEmtUueusc7jkBz7gJ12vnTHIxviZM5rzcq4tyCbZO7Kb37RqZg5kbYGK
	PfErhUwUIin7jsNVE7coB`)
	//nolint:lll
	fakeCipherText = []byte("lfQPTa6jwMTABaJhcrfVkoqcdyMVAettMsqgKXIALSKG5UpoYKbT/WgZjOiuCmEI0E/7piP8VATLOAHKDBNF2WrQOKSYF+gdHkh4NLv0cW0NZ2qyZeWhknywE6063ylhCYjJOrJA1z12i2bHHbjZZGfqkwfzyxxFLTv6jSbalpZ4oZcUcNY/DrtVk/K01qZw6o4l1f0FUL6UZVSirn+B3YDWLeVQ0FGr6jlhCpN203Rf688nqdBvhw4bUEQiykCMxWm2/rJBNWm2SzZgw65kb4W0ph1qjcoUjXBwNakK+E0Lw/fwi8+bUC1lkT8+hJpMLKZkzb07rbGAnmljQo0NkqJh4kl+aycsEhm9bZj+b6w0r795YugyNsyca5CnUvkB1Dg")
	fakeKey        = []byte("u3K0eKsmGl76jY1buzexwYoRRLLQrQck")
)

func TestEncryptDataBlock(t *testing.T) {
	testCase := []struct {
		Text string
		Key  string
		Ok   bool
	}{
		{
			Text: "hello world, my name is Gatekeeper",
			Key:  "DtNMS2eO7Fi5vsuLrW55nrRbir2kPfTw",
			Ok:   true,
		},
		{
			Text: "hello world, my name is Gatekeeper",
			Key:  "DtNMS2eO7Fi5vsu",
		},
		{
			Text: "h",
			Key:  "DtNMS2eO7Fi5vsuLrW55nrRbir2kPfTwtr",
		},
	}

	for idx, test := range testCase {
		_, err := encryption.EncryptDataBlock(
			bytes.NewBufferString(test.Text).Bytes(),
			bytes.NewBufferString(test.Key).Bytes(),
		)
		if err != nil && test.Ok {
			t.Errorf("test case: %d should not have failed, %s", idx, err)
		}
	}
}

func TestEncodeText(t *testing.T) {
	session, err := encryption.EncodeText("12245325632323263762", "1gjrlcjQ8RyKANngp9607txr5fF5fhf1")
	assert.NotEmpty(t, session)
	require.NoError(t, err)
}

func BenchmarkEncryptDataBlock(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, _ = encryption.EncryptDataBlock(fakePlainText, fakeKey)
	}
}

func BenchmarkEncodeText(b *testing.B) {
	text := string(fakePlainText)
	key := string(fakeKey)
	for n := 0; n < b.N; n++ {
		_, _ = encryption.EncodeText(text, key)
	}
}

func BenchmarkDecodeText(b *testing.B) {
	t := string(fakeCipherText)
	k := string(fakeKey)
	for n := 0; n < b.N; n++ {
		if _, err := encryption.DecodeText(t, k); err != nil {
			b.FailNow()
		}
	}
}

func TestDecodeText(t *testing.T) {
	fakeKey := "HYLNt2JSzD7Lpz0djTRudmlOpbwx1oHB"
	fakeText := "12245325632323263762"

	encrypted, err := encryption.EncodeText(fakeText, fakeKey)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	decoded, _ := encryption.DecodeText(encrypted, fakeKey)
	assert.NotNil(t, decoded, "the session should not have been nil")
	assert.Equal(t, decoded, fakeText, "the decoded text is not the same")
}

func TestDecryptDataBlock(t *testing.T) {
	testCase := []struct {
		Text string
		Key  string
		Ok   bool
	}{
		{
			Text: "hello world, my name is Gatekeeper",
			Key:  "DtNMS2eO7Fi5vsuLrW55nrRbir2kPfss",
			Ok:   true,
		},
		{
			Text: "h",
			Key:  "DtNMS2eO7Fi5vsuLrW55nrRbir2kPfTw",
			Ok:   true,
		},
	}

	for idx, test := range testCase {
		cipher, err := encryption.EncryptDataBlock(
			bytes.NewBufferString(test.Text).Bytes(),
			bytes.NewBufferString(test.Key).Bytes(),
		)
		if err != nil && test.Ok {
			t.Errorf("test case: %d should not have failed, %s", idx, err)
		}

		plain, err := encryption.DecryptDataBlock(
			cipher,
			bytes.NewBufferString(test.Key).Bytes(),
		)
		if err != nil {
			t.Errorf("test case: %d should not have failed, %s", idx, err)
		}

		if string(plain) != test.Text {
			t.Errorf("test case: %d are not the same", idx)
		}
	}
}
