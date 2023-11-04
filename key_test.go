// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
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
			c, closeCard := newTestCard(t)
			defer closeCard()

			k := Key{
				Algorithm:   AlgorithmEC256,
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

			if !supportsAttestation(c) {
				auth.PINPolicy = test.policy
			}

			priv, err := c.PrivateKey(SlotAuthentication, pub, auth)
			require.NoError(t, err, "Failed to build private key")

			s, ok := priv.(crypto.Signer)
			require.True(t, ok, "Expected crypto.Signer: got=%T", priv)

			data := sha256.Sum256([]byte("foo"))

			_, err = s.Sign(rand.Reader, data[:], crypto.SHA256)
			assert.NoError(t, err, "Failed to sign")

			_, err = s.Sign(rand.Reader, data[:], crypto.SHA256)
			assert.NoError(t, err, "Failed to sign")

			assert.Equal(t, test.want, got, "PINPrompt called %d times, want=%d", got, test.want)
		})
	}
}

func TestDecryptRSA(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
		long bool
	}{
		{"rsa1024", AlgorithmRSA1024, false},
		{"rsa2048", AlgorithmRSA2048, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.long && testing.Short() {
				t.Skip("skipping test in short mode")
			}
			c, closeCard := newTestCard(t)
			defer closeCard()
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
			ct, err := rsa.EncryptPKCS1v15(rand.Reader, pub, data)
			require.NoError(t, err, "Failed to encrypt")

			priv, err := c.PrivateKey(slot, pub, KeyAuth{})
			require.NoError(t, err, "Failed to get private key")

			d, ok := priv.(crypto.Decrypter)
			require.True(t, ok, "Private key didn't implement crypto.Decrypter")

			got, err := d.Decrypt(rand.Reader, ct, nil)
			require.NoError(t, err, "Failed to decrypt")

			assert.Equal(t, data, got, "Failed to decrypt, got=%q, want=%q", got, data)
		})
	}
}

func TestStoreCertificate(t *testing.T) {
	c, closeCard := newTestCard(t)
	defer closeCard()
	slot := SlotAuthentication

	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generating CA private key")

	// Generate a self-signed certificate
	caTmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "my-ca"},
		SerialNumber:          big.NewInt(100),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPriv.Public(), caPriv)
	require.NoError(t, err, "Failed to generate self-signed certificate")

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err, "Failed to parse CA cert")

	key := Key{
		Algorithm:   AlgorithmEC256,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyNever,
	}
	pub, err := c.GenerateKey(DefaultManagementKey, slot, key)
	require.NoError(t, err, "Failed to generate key")

	cliTmpl := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "my-client"},
		SerialNumber: big.NewInt(101),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliCertDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, pub, caPriv)
	require.NoError(t, err, "Failed to create client certificate")

	cliCert, err := x509.ParseCertificate(cliCertDER)
	require.NoError(t, err, "Failed to parse CLI certificate")

	err = c.SetCertificate(DefaultManagementKey, slot, cliCert)
	require.NoError(t, err, "Failed to store client certificate")

	gotCert, err := c.Certificate(slot)
	require.NoError(t, err, "Failed to get client certificate")
	assert.Equal(t, cliCert.Raw, gotCert.Raw, "Stored certificate didn't match cert retrieved")
}

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
		bits int
		long bool // Does the key generation take a long time?
	}{
		{
			name: "ec_256",
			alg:  AlgorithmEC256,
		},
		{
			name: "ec_384",
			alg:  AlgorithmEC384,
		},
		{
			name: "rsa_1024",
			alg:  AlgorithmRSA1024,
		},
		{
			name: "rsa_2048",
			alg:  AlgorithmRSA2048,
			long: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.long && testing.Short() {
				t.Skip("skipping test in short mode")
			}
			c, closeCard := newTestCard(t)
			defer closeCard()
			if test.alg == AlgorithmEC384 {
				testRequiresVersion(t, c, 4, 3, 0)
			}

			key := Key{
				Algorithm:   test.alg,
				TouchPolicy: TouchPolicyNever,
				PINPolicy:   PINPolicyNever,
			}

			_, err := c.GenerateKey(DefaultManagementKey, SlotAuthentication, key)
			assert.NoError(t, err, "Failed to generate key")
		})
	}
}

func TestPrivateKey(t *testing.T) {
	alg := AlgorithmEC256
	slot := SlotAuthentication

	c, closeCard := newTestCard(t)
	defer closeCard()

	key := Key{
		Algorithm:   alg,
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
	sig, err := signer.Sign(rand.Reader, hash, crypto.SHA256)
	require.NoError(t, err, "Failed to sign")

	var ecdsaSignature struct {
		R, S *big.Int
	}

	_, err = asn1.Unmarshal(sig, &ecdsaSignature)
	require.NoError(t, err, "Failed to unmarshal")

	ok = ecdsa.Verify(ecdsaPub, hash, ecdsaSignature.R, ecdsaSignature.S)
	require.True(t, ok, "Failed to validate signature")
}

func TestPrivateKeyPINError(t *testing.T) {
	slot := SlotAuthentication

	c, closeCard := newTestCard(t)
	defer closeCard()

	key := Key{
		Algorithm:   AlgorithmEC256,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyAlways,
	}
	pub, err := c.GenerateKey(DefaultManagementKey, slot, key)
	require.NoError(t, err, "Failed to generate key")

	auth := KeyAuth{
		PINPrompt: func() (string, error) {
			return "", errors.New("test error") //nolint:goerr113
		},
	}

	priv, err := c.PrivateKey(slot, pub, auth)
	require.NoError(t, err, "Failed to get private key")

	signer, ok := priv.(crypto.Signer)
	require.True(t, ok, "Private key doesn't implement crypto.Signer")

	b := sha256.Sum256([]byte("hello"))
	hash := b[:]

	_, err = signer.Sign(rand.Reader, hash, crypto.SHA256)
	assert.Error(t, err, "Expected sign to fail with PIN prompt that returned error")
}

var (
	//go:embed certs/test/ValidChain.crt
	validChainCert string
	//go:embed certs/test/ValidChain.key
	validChainKey string

	//go:embed certs/test/ValidChain2018.crt
	validChain2018Cert string
	//go:embed certs/test/ValidChain2018.key
	validChain2018Key string

	//go:embed certs/test/InvalidChain.crt
	invalidChainCert string
	//go:embed certs/test/InvalidChain.key
	invalidChainKey string

	//go:embed certs/test/InvalidChain2.crt
	invalidChain2Cert string
	//go:embed certs/test/InvalidChain2.key
	invalidChain2Key string
)

func TestVerify(t *testing.T) {
	tests := []struct {
		name       string
		deviceCert string
		keyCert    string
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

	parseCert := func(cert string) (*x509.Certificate, error) {
		block, _ := pem.Decode([]byte(cert))
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

// ephemeralKey generates an ephemeral key for the given algorithm.
func ephemeralKey(t *testing.T, alg Algorithm) privateKey {
	t.Helper()
	var (
		key privateKey
		err error
	)
	switch alg {
	case AlgorithmEC256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgorithmEC384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case AlgorithmEd25519:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case AlgorithmRSA1024:
		key, err = rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec
	case AlgorithmRSA2048:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		t.Fatalf("ephemeral key: unknown algorithm %d", alg)
	}

	require.NoError(t, err, "Failed to generate ephemeral key")

	return key
}
