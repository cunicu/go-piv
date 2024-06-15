// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"cunicu.li/go-iso7816/filter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "embed"
)

var (
	errUnexpectedValue   = errors.New("unexpected value")
	errUnexpectedVersion = errors.New("unexpected version")
)

func TestPINPrompt(t *testing.T) {
	tests := []struct {
		name   string
		policy PINPolicy
		want   int
	}{
		{"Never", PINPolicyNever, 0},
		{"Once", PINPolicyOnce, 1},
		{"Always", PINPolicyAlways, 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withCard(t, false, false, nil, func(t *testing.T, c *Card) {
				k := Key{
					Algorithm:   AlgECCP256,
					PINPolicy:   test.policy,
					TouchPolicy: TouchPolicyNever,
				}
				pub, err := c.GenerateKey(DefaultManagementKey, SlotAuthentication, k)
				require.NoError(t, err, "Failed to generate key on slot")

				got := 0
				auth := KeyAuth{
					PINPrompt: func() (string, error) {
						got++
						return DefaultPIN, nil
					},
				}

				if !c.SupportsAttestation() {
					auth.PINPolicy = test.policy
				}

				priv, err := c.PrivateKey(SlotAuthentication, pub, auth)
				require.NoError(t, err, "Failed to build private key")

				s, ok := priv.(crypto.Signer)
				require.True(t, ok, "Expected crypto.Signer: got=%T", priv)

				data := sha256.Sum256([]byte("foo"))

				_, err = s.Sign(c.Rand, data[:], crypto.SHA256)
				assert.NoError(t, err, "Failed to sign")

				_, err = s.Sign(c.Rand, data[:], crypto.SHA256)
				assert.NoError(t, err, "Failed to sign")

				assert.Equal(t, test.want, got, "PINPrompt called %d times, want=%d", got, test.want)
			})
		})
	}
}

func TestDecryptRSA(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
		long bool
	}{
		{"RSA/1024", AlgRSA1024, false},
		{"RSA/2048", AlgRSA2048, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withCard(t, false, test.long, nil, func(t *testing.T, c *Card) {
				slot := SlotAuthentication
				key := Key{
					Algorithm:   test.alg,
					TouchPolicy: TouchPolicyNever,
					PINPolicy:   PINPolicyNever,
				}

				pubKey, err := c.GenerateKey(DefaultManagementKey, slot, key)
				require.NoError(t, err, "Failed to generate key")

				pub, ok := pubKey.(*rsa.PublicKey)
				require.True(t, ok, "Public key is not an RSA key")

				data := []byte("hello")
				ct, err := rsa.EncryptPKCS1v15(c.Rand, pub, data)
				require.NoError(t, err, "Failed to encrypt")

				priv, err := c.PrivateKey(slot, pub, KeyAuth{})
				require.NoError(t, err, "Failed to get private key")

				d, ok := priv.(crypto.Decrypter)
				require.True(t, ok, "Private key didn't implement crypto.Decrypter")

				got, err := d.Decrypt(c.Rand, ct, nil)
				require.NoError(t, err, "Failed to decrypt")

				assert.Equal(t, data, got, "Failed to decrypt, got=%q, want=%q", got, data)
			})
		})
	}
}

func TestStoreCertificate(t *testing.T) {
	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		slot := SlotAuthentication

		caPriv := testKey(t, AlgTypeECCP, 256)

		// Generate a self-signed certificate
		caTmpl := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "my-ca",
			},
			SerialNumber:          big.NewInt(100),
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage: x509.KeyUsageKeyEncipherment |
				x509.KeyUsageDigitalSignature |
				x509.KeyUsageCertSign,
		}

		// Certificate must be deterministic for
		// reproducible tests
		caTmpl.NotBefore, _ = time.Parse(time.DateOnly, "2020-01-01")
		caTmpl.NotAfter, _ = time.Parse(time.DateOnly, "2030-01-01")

		caCertDER, err := x509.CreateCertificate(c.Rand, caTmpl, caTmpl, caPriv.Public(), caPriv)
		require.NoError(t, err, "Failed to generate self-signed certificate")

		caCert, err := x509.ParseCertificate(caCertDER)
		require.NoError(t, err, "Failed to parse CA cert")

		key := Key{
			Algorithm:   AlgECCP256,
			TouchPolicy: TouchPolicyNever,
			PINPolicy:   PINPolicyNever,
		}

		pub, err := c.GenerateKey(DefaultManagementKey, slot, key)
		require.NoError(t, err, "Failed to generate key")

		cliTmpl := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "my-client",
			},
			SerialNumber: big.NewInt(101),
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		// Certificate must be deterministic for
		// reproducible tests
		cliTmpl.NotBefore, _ = time.Parse(time.DateOnly, "2020-01-01")
		cliTmpl.NotAfter, _ = time.Parse(time.DateOnly, "2030-01-01")

		cliCertDER, err := x509.CreateCertificate(c.Rand, cliTmpl, caCert, pub, caPriv)
		require.NoError(t, err, "Failed to create client certificate")

		cliCert, err := x509.ParseCertificate(cliCertDER)
		require.NoError(t, err, "Failed to parse CLI certificate")

		err = c.SetCertificate(DefaultManagementKey, slot, cliCert)
		require.NoError(t, err, "Failed to store client certificate")

		gotCert, err := c.Certificate(slot)
		require.NoError(t, err, "Failed to get client certificate")
		assert.Equal(t, cliCert.Raw, gotCert.Raw, "Stored certificate didn't match cert retrieved")
	})
}

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
		bits int
		long bool
	}{
		{
			name: "EC/P256",
			alg:  AlgECCP256,
		},
		{
			name: "EC/P384",
			alg:  AlgECCP384,
		},
		{
			name: "RSA/1024",
			alg:  AlgRSA1024,
		},
		{
			name: "RSA/2048",
			alg:  AlgRSA2048,
			long: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var flt filter.Filter
			if test.alg == AlgECCP384 {
				flt = SupportsAlgorithmEC384
			}

			withCard(t, false, test.long, flt, func(t *testing.T, c *Card) {
				key := Key{
					Algorithm:   test.alg,
					TouchPolicy: TouchPolicyNever,
					PINPolicy:   PINPolicyNever,
				}

				_, err := c.GenerateKey(DefaultManagementKey, SlotAuthentication, key)
				assert.NoError(t, err, "Failed to generate key")
			})
		})
	}
}

func TestPrivateKey(t *testing.T) {
	slot := SlotAuthentication

	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		key := Key{
			Algorithm:   AlgECCP256,
			TouchPolicy: TouchPolicyNever,
			PINPolicy:   PINPolicyNever,
		}
		pub, err := c.GenerateKey(DefaultManagementKey, slot, key)
		require.NoError(t, err, "Failed to generate key")

		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		require.True(t, ok, "Public key is not an *ecdsa.PublicKey: %T", pub)

		auth := KeyAuth{PIN: DefaultPIN}
		priv, err := c.PrivateKey(slot, pub, auth)
		require.NoError(t, err, "Failed to get private key")

		signer, ok := priv.(crypto.Signer)
		require.True(t, ok, "Private key doesn't implement crypto.Signer")

		b := sha256.Sum256([]byte("hello"))
		hash := b[:]
		sig, err := signer.Sign(c.Rand, hash, crypto.SHA256)
		require.NoError(t, err, "Failed to sign")

		var ecdsaSignature struct {
			R, S *big.Int
		}

		_, err = asn1.Unmarshal(sig, &ecdsaSignature)
		require.NoError(t, err, "Failed to unmarshal")

		ok = ecdsa.Verify(ecdsaPub, hash, ecdsaSignature.R, ecdsaSignature.S)
		require.True(t, ok, "Failed to validate signature")
	})
}

func TestPrivateKeyPINError(t *testing.T) {
	slot := SlotAuthentication

	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		key := Key{
			Algorithm:   AlgECCP256,
			TouchPolicy: TouchPolicyNever,
			PINPolicy:   PINPolicyAlways,
		}
		pub, err := c.GenerateKey(DefaultManagementKey, slot, key)
		require.NoError(t, err, "Failed to generate key")

		auth := KeyAuth{
			PINPrompt: func() (string, error) {
				return "", errors.New("test error") //nolint:err113
			},
		}

		priv, err := c.PrivateKey(slot, pub, auth)
		require.NoError(t, err, "Failed to get private key")

		signer, ok := priv.(crypto.Signer)
		require.True(t, ok, "Private key doesn't implement crypto.Signer")

		b := sha256.Sum256([]byte("hello"))
		hash := b[:]

		_, err = signer.Sign(c.Rand, hash, crypto.SHA256)
		assert.Error(t, err, "Expected sign to fail with PIN prompt that returned error")
	})
}

var (
	//go:embed certs/test/ValidChain.crt
	validChainCert []byte
	//go:embed certs/test/ValidChain.key
	validChainKey []byte

	//go:embed certs/test/ValidChain2018.crt
	validChain2018Cert []byte
	//go:embed certs/test/ValidChain2018.key
	validChain2018Key []byte

	//go:embed certs/test/InvalidChain.crt
	invalidChainCert []byte
	//go:embed certs/test/InvalidChain.key
	invalidChainKey []byte

	//go:embed certs/test/InvalidChain2.crt
	invalidChain2Cert []byte
	//go:embed certs/test/InvalidChain2.key
	invalidChain2Key []byte
)

func TestVerify(t *testing.T) {
	tests := []struct {
		name       string
		deviceCert []byte
		keyCert    []byte
		ok         bool
	}{
		{
			// Valid attestation chain from a recent YubiKey.
			name:       "ValidChain",
			deviceCert: validChainCert,
			keyCert:    validChainKey,
			ok:         true,
		},
		{
			// Valid attestation chain from a YubiKey manufactured in 2018 showing a manufacture bug (device certified using U2F root, and device cert does not encode X509 basic constraints).
			name:       "ValidChain2018",
			deviceCert: validChain2018Cert,
			keyCert:    validChain2018Key,
			ok:         true,
		},
		{
			// Invalid attestation chain. Device cert from YubiKey A, key cert from YubiKey B.
			name:       "InvalidChain",
			deviceCert: invalidChainCert,
			keyCert:    invalidChainKey,
			ok:         false,
		},
		{
			// Invalid attestation chain. Device cert from YubiKey B, key cert from YubiKey A.
			name:       "InvalidChain2",
			deviceCert: invalidChain2Cert,
			keyCert:    invalidChain2Key,
			ok:         false,
		},
	}

	parseCert := func(cert []byte) (*x509.Certificate, error) {
		block, _ := pem.Decode(cert)
		require.NotNil(t, block, "Decoding PEM cert, empty block")

		return x509.ParseCertificate(block.Bytes)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deviceCert, err := parseCert(test.deviceCert)
			require.NoError(t, err, "Failed to parse device cert")

			keyCert, err := parseCert(test.keyCert)
			require.NoError(t, err, "Failed to parse key cert")

			_, err = Verify(deviceCert, keyCert)
			assert.Equal(t, (err == nil), test.ok, "Verify returned %v, expected test outcome %v", err, test.ok)
		})
	}
}

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

	//go:embed testdata/RSA_512.key
	testKeyRSA512 []byte
	//go:embed testdata/RSA_1024.key
	testKeyRSA1024 []byte
	//go:embed testdata/RSA_2048.key
	testKeyRSA2048 []byte
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

	case AlgTypeRSA:
		switch bits {
		case 512:
			testKey = testKeyRSA512
		case 1024:
			testKey = testKeyRSA1024
		case 2048:
			testKey = testKeyRSA2048
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
