// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

// privateKey is an interface with the optional (but always supported) methods
// of crypto.PrivateKey.
type privateKey interface {
	Equal(crypto.PrivateKey) bool
	Public() crypto.PublicKey
}

var (
	//go:embed testdata/EC_224.key
	testKeyEC224 []byte
	//go:embed testdata/EC_256.key
	testKeyEC256 []byte
	//go:embed testdata/EC_384.key
	testKeyEC384 []byte
	//go:embed testdata/EC_521.key
	testKeyEC521 []byte

	//go:embed testdata/Ed25519.key
	testKeyEd25519 []byte
	//go:embed testdata/X25519.key
	testKeyX25519 []byte

	//go:embed testdata/RSA_512.key
	testKeyRSA512 []byte
	//go:embed testdata/RSA_1024.key
	testKeyRSA1024 []byte
	//go:embed testdata/RSA_2048.key
	testKeyRSA2048 []byte
	//go:embed testdata/RSA_3072.key
	testKeyRSA3072 []byte
	//go:embed testdata/RSA_4096.key
	testKeyRSA4096 []byte
)

// testKey returns a deterministic key for testing
// We require deterministic keys for reproducible tests
// in order for the test transcript to match
func testKey(t *testing.T, typ algorithmType, bits int) (key privateKey) {
	t.Helper()

	var testKey []byte
	var err error
	switch typ {
	case AlgTypeECCP:
		switch bits {
		case 224:
			testKey = testKeyEC224
		case 256:
			testKey = testKeyEC256
		case 384:
			testKey = testKeyEC384
		case 521:
			testKey = testKeyEC521
		}

		b, _ := pem.Decode(testKey)
		require.NotNil(t, b)

		key, err = x509.ParseECPrivateKey(b.Bytes)
		require.NoError(t, err)

	case AlgTypeEd25519:
		b, _ := pem.Decode(testKeyEd25519)
		require.NotNil(t, b)
		require.Len(t, b.Bytes, 32)

		key = ed25519.PrivateKey(b.Bytes)

	case AlgTypeX25519:
		b, _ := pem.Decode(testKeyX25519)
		require.NotNil(t, b)
		require.Len(t, b.Bytes, 32)

		key, err = ecdh.X25519().NewPrivateKey(b.Bytes)
		require.NoError(t, err)

	case AlgTypeRSA:
		switch bits {
		case 512:
			testKey = testKeyRSA512
		case 1024:
			testKey = testKeyRSA1024
		case 2048:
			testKey = testKeyRSA2048
		case 3072:
			testKey = testKeyRSA3072
		case 4096:
			testKey = testKeyRSA4096
		}

		b, _ := pem.Decode(testKey)
		require.NotNil(t, b)

		key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
		require.NoError(t, err)

	default:
		t.Fatalf("ephemeral key: unknown algorithm")
	}

	return key
}
