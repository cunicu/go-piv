// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
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

	"cunicu.li/go-iso7816"
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
		alg  Algorithm
		long bool
	}{
		{AlgRSA1024, false},
		{AlgRSA2048, true},
		{AlgRSA3072, true},
		{AlgRSA4096, true},
	}
	for _, test := range tests {
		t.Run(test.alg.String(), func(t *testing.T) {
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

		caPriv := testKey(t, AlgECCP256)

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
		alg  Algorithm
		long bool
	}{
		{
			alg: AlgECCP256,
		},
		{
			alg: AlgECCP384,
		},
		{
			alg: AlgRSA1024,
		},
		{
			alg:  AlgRSA2048,
			long: true,
		},
		{
			alg:  AlgRSA3072,
			long: true,
		},
		{
			alg:  AlgRSA4096,
			long: true,
		},
	}
	for _, test := range tests {
		t.Run(test.alg.String(), func(t *testing.T) {
			withCard(t, false, test.long, SupportsAlgorithm(test.alg), func(t *testing.T, c *Card) {
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

func TestMoveKey(t *testing.T) {
	withCard(t, true, false, SupportsKeyMoveDelete, func(t *testing.T, c *Card) {
		// Moving non-existing key must fail
		err := c.MoveKey(DefaultManagementKey, SlotAuthentication, SlotCardAuthentication)
		require.ErrorIs(t, err, iso7816.ErrReferenceNotFound, "Expected move of non-existing key to fail")

		// Generate key
		_, err = c.GenerateKey(DefaultManagementKey, SlotAuthentication, Key{
			Algorithm:   AlgRSA1024,
			PINPolicy:   PINPolicyNever,
			TouchPolicy: TouchPolicyNever,
		})
		require.NoErrorf(t, err, "Generation of new key failed: %w", err)

		// Check that new key exists
		m1, err := c.Metadata(SlotAuthentication)
		require.NoErrorf(t, err, "Failed to retrieve metadata of new key: %w", err)
		require.Equal(t, m1.Algorithm, AlgRSA1024, "Mismatching algorithm for new key")

		pk1, ok := m1.PublicKey.(*rsa.PublicKey)
		require.True(t, ok, "Key is not an RSA key")

		// Move key
		err = c.MoveKey(DefaultManagementKey, SlotAuthentication, SlotCardAuthentication)
		require.NoErrorf(t, err, "Failed to move key: %w", err)

		// Check key has been removed from source slot
		_, err = c.Metadata(SlotAuthentication)
		require.ErrorIs(t, err, iso7816.ErrReferenceNotFound, "Key still exists")

		// Check key is now in the new slot
		m2, err := c.Metadata(SlotCardAuthentication)
		require.NoErrorf(t, err, "Failed to retrieve metadata of moved key: %w", err)

		pk2, ok := m2.PublicKey.(*rsa.PublicKey)
		require.True(t, ok, "Key is not an RSA key")

		require.True(t, pk1.Equal(pk2), "Public keys of moved slot are not equal")
	})
}

func TestDeleteKey(t *testing.T) {
	withCard(t, true, false, SupportsKeyMoveDelete, func(t *testing.T, c *Card) {
		// Delete non-existing key must fail
		err := c.DeleteKey(DefaultManagementKey, SlotAuthentication)
		require.ErrorIs(t, err, iso7816.ErrReferenceNotFound, "Deletion of non-existing key succeeded")

		// Generate key
		_, err = c.GenerateKey(DefaultManagementKey, SlotAuthentication, Key{
			Algorithm:   AlgRSA1024,
			PINPolicy:   PINPolicyNever,
			TouchPolicy: TouchPolicyNever,
		})
		require.NoErrorf(t, err, "Failed to generate key: %w", err)

		// Check that new key exists
		m, err := c.Metadata(SlotAuthentication)
		require.NoErrorf(t, err, "Failed to retrieve metadata of new key: %w", err)
		require.Equal(t, m.Algorithm, AlgRSA1024, "Key is not an RSA key")

		// Delete key
		err = c.DeleteKey(DefaultManagementKey, SlotAuthentication)
		require.NoErrorf(t, err, "Failed to delete key: %w", err)

		// Check key has been removed
		_, err = c.Metadata(SlotAuthentication)
		require.ErrorIs(t, err, iso7816.ErrReferenceNotFound, "Key has not been removed")
	})
}
