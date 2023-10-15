// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"bytes"
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
			yk, closeCard := newTestYubiKey(t)
			defer closeCard()

			k := Key{
				Algorithm:   AlgorithmEC256,
				PINPolicy:   test.policy,
				TouchPolicy: TouchPolicyNever,
			}
			pub, err := yk.GenerateKey(DefaultManagementKey, SlotAuthentication, k)
			if err != nil {
				t.Fatalf("generating key on slot: %v", err)
			}
			got := 0
			auth := KeyAuth{
				PINPrompt: func() (string, error) {
					got++
					return DefaultPIN, nil
				},
			}

			if !supportsAttestation(yk) {
				auth.PINPolicy = test.policy
			}

			priv, err := yk.PrivateKey(SlotAuthentication, pub, auth)
			if err != nil {
				t.Fatalf("building private key: %v", err)
			}
			s, ok := priv.(crypto.Signer)
			if !ok {
				t.Fatalf("expected crypto.Signer: got=%T", priv)
			}
			data := sha256.Sum256([]byte("foo"))
			if _, err := s.Sign(rand.Reader, data[:], crypto.SHA256); err != nil {
				t.Errorf("signing error: %v", err)
			}
			if _, err := s.Sign(rand.Reader, data[:], crypto.SHA256); err != nil {
				t.Errorf("signing error: %v", err)
			}
			if got != test.want {
				t.Errorf("PINPrompt called %d times, want=%d", got, test.want)
			}
		})
	}
}

func TestYubiKeyDecryptRSA(t *testing.T) {
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
			yk, closeCard := newTestYubiKey(t)
			defer closeCard()
			slot := SlotAuthentication
			key := Key{
				Algorithm:   test.alg,
				TouchPolicy: TouchPolicyNever,
				PINPolicy:   PINPolicyNever,
			}
			pubKey, err := yk.GenerateKey(DefaultManagementKey, slot, key)
			if err != nil {
				t.Fatalf("generating key: %v", err)
			}
			pub, ok := pubKey.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("public key is not an rsa key")
			}

			data := []byte("hello")
			ct, err := rsa.EncryptPKCS1v15(rand.Reader, pub, data)
			if err != nil {
				t.Fatalf("encryption failed: %v", err)
			}

			priv, err := yk.PrivateKey(slot, pub, KeyAuth{})
			if err != nil {
				t.Fatalf("getting private key: %v", err)
			}
			d, ok := priv.(crypto.Decrypter)
			if !ok {
				t.Fatalf("private key didn't implement crypto.Decypter")
			}
			got, err := d.Decrypt(rand.Reader, ct, nil)
			if err != nil {
				t.Fatalf("decryption failed: %v", err)
			}
			if !bytes.Equal(data, got) {
				t.Errorf("decrypt, got=%q, want=%q", got, data)
			}
		})
	}
}

func TestYubiKeyStoreCertificate(t *testing.T) {
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()
	slot := SlotAuthentication

	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ca private: %v", err)
	}
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
	if err != nil {
		t.Fatalf("generating self-signed certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parsing ca cert: %v", err)
	}

	key := Key{
		Algorithm:   AlgorithmEC256,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyNever,
	}
	pub, err := yk.GenerateKey(DefaultManagementKey, slot, key)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	cliTmpl := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "my-client"},
		SerialNumber: big.NewInt(101),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliCertDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, pub, caPriv)
	if err != nil {
		t.Fatalf("creating client cert: %v", err)
	}
	cliCert, err := x509.ParseCertificate(cliCertDER)
	if err != nil {
		t.Fatalf("parsing cli cert: %v", err)
	}
	if err := yk.SetCertificate(DefaultManagementKey, slot, cliCert); err != nil {
		t.Fatalf("storing client cert: %v", err)
	}
	gotCert, err := yk.Certificate(slot)
	if err != nil {
		t.Fatalf("getting client cert: %v", err)
	}
	if !bytes.Equal(gotCert.Raw, cliCert.Raw) {
		t.Errorf("stored cert didn't match cert retrieved")
	}
}

func TestYubiKeyGenerateKey(t *testing.T) {
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
			yk, closeCard := newTestYubiKey(t)
			defer closeCard()
			if test.alg == AlgorithmEC384 {
				testRequiresVersion(t, yk, 4, 3, 0)
			}

			key := Key{
				Algorithm:   test.alg,
				TouchPolicy: TouchPolicyNever,
				PINPolicy:   PINPolicyNever,
			}
			if _, err := yk.GenerateKey(DefaultManagementKey, SlotAuthentication, key); err != nil {
				t.Errorf("generating key: %v", err)
			}
		})
	}
}

func TestYubiKeyPrivateKey(t *testing.T) {
	alg := AlgorithmEC256
	slot := SlotAuthentication

	yk, closeCard := newTestYubiKey(t)
	defer closeCard()

	key := Key{
		Algorithm:   alg,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyNever,
	}
	pub, err := yk.GenerateKey(DefaultManagementKey, slot, key)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not an *ecdsa.PublicKey: %T", pub)
	}

	auth := KeyAuth{PIN: DefaultPIN}
	priv, err := yk.PrivateKey(slot, pub, auth)
	if err != nil {
		t.Fatalf("getting private key: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("private key doesn't implement crypto.Signer")
	}

	b := sha256.Sum256([]byte("hello"))
	hash := b[:]
	sig, err := signer.Sign(rand.Reader, hash, crypto.SHA256)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	var ecdsaSignature struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sig, &ecdsaSignature); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !ecdsa.Verify(ecdsaPub, hash, ecdsaSignature.R, ecdsaSignature.S) {
		t.Fatalf("signature validation failed")
	}
}

func TestYubiKeyPrivateKeyPINError(t *testing.T) {
	alg := AlgorithmEC256
	slot := SlotAuthentication

	yk, closeCard := newTestYubiKey(t)
	defer closeCard()

	key := Key{
		Algorithm:   alg,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyAlways,
	}
	pub, err := yk.GenerateKey(DefaultManagementKey, slot, key)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	auth := KeyAuth{
		PINPrompt: func() (string, error) {
			return "", errors.New("test error") //nolint:goerr113
		},
	}

	priv, err := yk.PrivateKey(slot, pub, auth)
	if err != nil {
		t.Fatalf("getting private key: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("private key doesn't implement crypto.Signer")
	}

	b := sha256.Sum256([]byte("hello"))
	hash := b[:]
	if _, err := signer.Sign(rand.Reader, hash, crypto.SHA256); err == nil {
		t.Errorf("expected sign to fail with pin prompt that returned error")
	}
}

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
			deviceCert: "-----BEGIN CERTIFICATE-----\nMIIC+jCCAeKgAwIBAgIJAKs/UIpBjg1uMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNV\nBAMMIFl1YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAw\nMDAwMFoYDzIwNTIwNDE3MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0\ndGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0zdJWGnk\naLE8Rb+TP7iSffhJV9SJEp2Me4QcfVidgHqyIdo0lruBk69RF1nrmS3i+G1yyUh/\nymAPZkcQCpms0E23Dmhue1VRpBedcsVtO/xSrfu0qAWTslp/k57ry6vkidrQU1cx\nl2KodH3KTmnZmaskQD8eGtxXwcmLOmhKem6GSqhN/3QznaDhZmVUAvUKSOaIzOxn\n2u1mDHhGwaHhR7dklsDwN7oni4WWX1GJXtzpB8j6JhoqyqXwSbq+ck54PfzUoOFd\n/2yKyFRDXnQvzbNL7+afbxBQQMxxo1e24DNE/cp+K09eT7Gh1Urao6meaSssN4aV\nFfmkhC2NapGKMQIDAQABoykwJzARBgorBgEEAYLECgMDBAMFBAMwEgYDVR0TAQH/\nBAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEAJfOLOQYGyIMQ5y+sDkYz+e6G\nH8BqqiYL9VOC3U3KQX9mrtZnaIexqJOCQyCFOSvaTFJvOfNiCCKQuLbmS+Qn4znd\nnSitCsdJSFKskQP7hbXqUK01epb6iTuuko4w3V57YVudnniZBD2s4XoNcJ6BFizZ\n3iXQqRMaLVfFHS9Qx0iLZLcR2s29nIl6NI/qFdIgkyo07J5cPnBiD6wxQft8FdfR\nbgx9yrrjY0mvj/k5LRN6lab8lTolgI5luJtKNueq96LVkTkAzcCaJPQ9YQ4cxeU9\nOapsEeOk6xf5bRPtdf0WhEKthXywt9D0pSHhAI+fpLNe/VtlZpt3hn9aTbqSug==\n-----END CERTIFICATE-----\n",
			keyCert:    "-----BEGIN CERTIFICATE-----\nMIICVTCCAT2gAwIBAgIQAU4Yg7Qnw9FZgMBEaJ7ZMzANBgkqhkiG9w0BAQsFADAh\nMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0dGVzdGF0aW9uMCAXDTE2MDMxNDAwMDAw\nMFoYDzIwNTIwNDE3MDAwMDAwWjAlMSMwIQYDVQQDDBpZdWJpS2V5IFBJViBBdHRl\nc3RhdGlvbiA5YTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABATzM3sJuwemL2Ha\nHkGIzmCVjUMreNIVrRLOvnbZjoVflk1eab/iLUlKzk/2jXTu9TISRg2dhyXcutct\nvnqr66yjTjBMMBEGCisGAQQBgsQKAwMEAwUEAzAUBgorBgEEAYLECgMHBAYCBADw\nDxQwEAYKKwYBBAGCxAoDCAQCAgEwDwYKKwYBBAGCxAoDCQQBBDANBgkqhkiG9w0B\nAQsFAAOCAQEAFX0hL5gi/g4ZM7vCH5kDAtma7eBp0LpbCzR313GGyBR7pJFtuj2l\nbWU+V3SFRihXBTDb8q+uvyCBqgz1szdZzrpfjqNkhEPfPNabxjxJxVoe6Gdcn115\naduxfqqT2u+YIsERzaIIIisehLQkc/5zLkpocA6jbKBZnZWUBJIxuz4QmYTIf0O4\nHPE2o4JbAyGx/hRaqVvDgNeAz94ZFjb4Mp3RNbbdRUZB0ehrT/IGRJoHRu2HKFGM\nylRJL2kjKPoEc4XHbCu+MfmAIrQ4Xseg85zyI7ThhYvAzktdLHhQyfYr4wrrLCN3\noeTzmiqIHe9AataJXQ+mEQEEc9TNY23RFg==\n-----END CERTIFICATE-----\n",
			ok:         true,
		},
		{
			// Valid attestation chain from a yubikey manufactured in 2018 showing a manufacture bug (device certified using U2F root, and device cert does not encode X509 basic constraints).
			name:       "ValidChain2018",
			deviceCert: "-----BEGIN CERTIFICATE-----\nMIIC6TCCAdGgAwIBAgIJALvwZFDESwMlMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNV\nBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgw\nMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElW\nIEF0dGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXnZ\n+lxX0nNzy3jn+lrZ+1cHTVUNYVKPqGTjvRw/7XOEnInWC1VCPJqwHYtnnoH4EIXN\n7kDGXwInfs9pwyjpgQw/V23yywFtUhaR8Xgw8zqC/YfJpeK4PetJ9/k+xFbICuX7\nWDv/k5Wth3VZSaVjm/tunWajtt3OLOQQaMSoLqP41XAHHuCyzfCwJ2Vsa2FyCINF\nyG6XobokeICDRnH44POqudcLVIDvZLQqu2LF+mZd+OO5nqmTa68kkwRf/m93eOJP\no7GvYtQSp7CPJC7ks2gl8U7wuT9DQT5/0wqkoEyLZg/KLUlzgXjMa+7GtCLTC1Ku\nOh9vw02f4K44RW4nWwIDAQABoxUwEzARBgorBgEEAYLECgMDBAMEAwcwDQYJKoZI\nhvcNAQELBQADggEBAHD/uXqNgCYywj2ee7s7kix2TT4XN9OIn0fTNh5LEiUN+q7U\nzJc9q7b5WD7PfaG6UNyuaSnLaq+dLOCJ4bX4h+/MwQSndQg0epMra1ThVQZkMkGa\nktAJ5JT6j9qxNxD1RWMl91e4JwtGzFyDwFyyUGnSwhMsqMdwfBsmTpvgxmAD/NMs\nkWB/m91FV9D+UBqsZRoLoc44kEFYBZ09ypTsR699oJRsBfG0AqVYyK7rnG6663fF\nGUSWk7noVdUPXedlwXCqCymCsVheoss9qF1cffaFIl9RxGvVvCFybx0LGiYDxfgv\n80yGZIY/mAqZVDWyHZSs4f6kWK9GeLKU2Y9yby4=\n-----END CERTIFICATE-----\n",
			keyCert:    "-----BEGIN CERTIFICATE-----\nMIICLzCCARegAwIBAgIRAIxiihk4fSKK6keqJYujvnkwDQYJKoZIhvcNAQELBQAw\nITEfMB0GA1UEAwwWWXViaWNvIFBJViBBdHRlc3RhdGlvbjAgFw0xNDA4MDEwMDAw\nMDBaGA8yMDUwMDkwNDAwMDAwMFowJTEjMCEGA1UEAwwaWXViaUtleSBQSVYgQXR0\nZXN0YXRpb24gOWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATHEzJsrhTHuvsx\n685AiWsAuT8Poe/zQfDRZNfpUSzJ31v6MZ9nz70pNrdd/sbG7O1UA6ceWhq1jHTU\n96Dnp99voycwJTARBgorBgEEAYLECgMDBAMEAwcwEAYKKwYBBAGCxAoDCAQCAgEw\nDQYJKoZIhvcNAQELBQADggEBADoswZ1LJ5GYVNgtRE0+zMQkAzam8YqeKmIDHtir\nvolIpGtJHzgCG2SdJlR/KnjRWF/1i8TRMhQ0O/KgkIEh+IyhJtD7DojgWvIBsCnX\nJXF7EPQMy17l7/9940QSOnQRIDb+z0eq9ACAjC3FWzqeR5VgN4C1QpCw7gKgqLTs\npmmDHHg4HsKl0PsPwim0bYIqEHttrLjPQiPnoa3qixzNKbwJjXb4/f/dvCTx9dRP\n0FVABj5Yh8f728xzrzw2nLZ9X/c0GoXfKu9s7lGNLcZ5OO+zys1ATei2h/PFJLDH\nAdrenw31WOYRtdjcNBKyAk80ajryjTAX3GXfbKpkdVB9hEo=\n-----END CERTIFICATE-----\n",
			ok:         true,
		},
		{
			// Invalid attestation chain. Device cert from yubikey A, key cert from yubikey B.
			name:       "InvalidChain",
			deviceCert: "-----BEGIN CERTIFICATE-----\nMIIC+jCCAeKgAwIBAgIJAKs/UIpBjg1uMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNV\nBAMMIFl1YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAw\nMDAwMFoYDzIwNTIwNDE3MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0\ndGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0zdJWGnk\naLE8Rb+TP7iSffhJV9SJEp2Me4QcfVidgHqyIdo0lruBk69RF1nrmS3i+G1yyUh/\nymAPZkcQCpms0E23Dmhue1VRpBedcsVtO/xSrfu0qAWTslp/k57ry6vkidrQU1cx\nl2KodH3KTmnZmaskQD8eGtxXwcmLOmhKem6GSqhN/3QznaDhZmVUAvUKSOaIzOxn\n2u1mDHhGwaHhR7dklsDwN7oni4WWX1GJXtzpB8j6JhoqyqXwSbq+ck54PfzUoOFd\n/2yKyFRDXnQvzbNL7+afbxBQQMxxo1e24DNE/cp+K09eT7Gh1Urao6meaSssN4aV\nFfmkhC2NapGKMQIDAQABoykwJzARBgorBgEEAYLECgMDBAMFBAMwEgYDVR0TAQH/\nBAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEAJfOLOQYGyIMQ5y+sDkYz+e6G\nH8BqqiYL9VOC3U3KQX9mrtZnaIexqJOCQyCFOSvaTFJvOfNiCCKQuLbmS+Qn4znd\nnSitCsdJSFKskQP7hbXqUK01epb6iTuuko4w3V57YVudnniZBD2s4XoNcJ6BFizZ\n3iXQqRMaLVfFHS9Qx0iLZLcR2s29nIl6NI/qFdIgkyo07J5cPnBiD6wxQft8FdfR\nbgx9yrrjY0mvj/k5LRN6lab8lTolgI5luJtKNueq96LVkTkAzcCaJPQ9YQ4cxeU9\nOapsEeOk6xf5bRPtdf0WhEKthXywt9D0pSHhAI+fpLNe/VtlZpt3hn9aTbqSug==\n-----END CERTIFICATE-----\n",
			keyCert:    "-----BEGIN CERTIFICATE-----\nMIICLzCCARegAwIBAgIRAIxiihk4fSKK6keqJYujvnkwDQYJKoZIhvcNAQELBQAw\nITEfMB0GA1UEAwwWWXViaWNvIFBJViBBdHRlc3RhdGlvbjAgFw0xNDA4MDEwMDAw\nMDBaGA8yMDUwMDkwNDAwMDAwMFowJTEjMCEGA1UEAwwaWXViaUtleSBQSVYgQXR0\nZXN0YXRpb24gOWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATHEzJsrhTHuvsx\n685AiWsAuT8Poe/zQfDRZNfpUSzJ31v6MZ9nz70pNrdd/sbG7O1UA6ceWhq1jHTU\n96Dnp99voycwJTARBgorBgEEAYLECgMDBAMEAwcwEAYKKwYBBAGCxAoDCAQCAgEw\nDQYJKoZIhvcNAQELBQADggEBADoswZ1LJ5GYVNgtRE0+zMQkAzam8YqeKmIDHtir\nvolIpGtJHzgCG2SdJlR/KnjRWF/1i8TRMhQ0O/KgkIEh+IyhJtD7DojgWvIBsCnX\nJXF7EPQMy17l7/9940QSOnQRIDb+z0eq9ACAjC3FWzqeR5VgN4C1QpCw7gKgqLTs\npmmDHHg4HsKl0PsPwim0bYIqEHttrLjPQiPnoa3qixzNKbwJjXb4/f/dvCTx9dRP\n0FVABj5Yh8f728xzrzw2nLZ9X/c0GoXfKu9s7lGNLcZ5OO+zys1ATei2h/PFJLDH\nAdrenw31WOYRtdjcNBKyAk80ajryjTAX3GXfbKpkdVB9hEo=\n-----END CERTIFICATE-----\n",
			ok:         false,
		},
		{
			// Invalid attestation chain. Device cert from yubikey B, key cert from yubikey A.
			name:       "InvalidChain2",
			deviceCert: "-----BEGIN CERTIFICATE-----\nMIIC6TCCAdGgAwIBAgIJALvwZFDESwMlMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNV\nBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgw\nMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElW\nIEF0dGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXnZ\n+lxX0nNzy3jn+lrZ+1cHTVUNYVKPqGTjvRw/7XOEnInWC1VCPJqwHYtnnoH4EIXN\n7kDGXwInfs9pwyjpgQw/V23yywFtUhaR8Xgw8zqC/YfJpeK4PetJ9/k+xFbICuX7\nWDv/k5Wth3VZSaVjm/tunWajtt3OLOQQaMSoLqP41XAHHuCyzfCwJ2Vsa2FyCINF\nyG6XobokeICDRnH44POqudcLVIDvZLQqu2LF+mZd+OO5nqmTa68kkwRf/m93eOJP\no7GvYtQSp7CPJC7ks2gl8U7wuT9DQT5/0wqkoEyLZg/KLUlzgXjMa+7GtCLTC1Ku\nOh9vw02f4K44RW4nWwIDAQABoxUwEzARBgorBgEEAYLECgMDBAMEAwcwDQYJKoZI\nhvcNAQELBQADggEBAHD/uXqNgCYywj2ee7s7kix2TT4XN9OIn0fTNh5LEiUN+q7U\nzJc9q7b5WD7PfaG6UNyuaSnLaq+dLOCJ4bX4h+/MwQSndQg0epMra1ThVQZkMkGa\nktAJ5JT6j9qxNxD1RWMl91e4JwtGzFyDwFyyUGnSwhMsqMdwfBsmTpvgxmAD/NMs\nkWB/m91FV9D+UBqsZRoLoc44kEFYBZ09ypTsR699oJRsBfG0AqVYyK7rnG6663fF\nGUSWk7noVdUPXedlwXCqCymCsVheoss9qF1cffaFIl9RxGvVvCFybx0LGiYDxfgv\n80yGZIY/mAqZVDWyHZSs4f6kWK9GeLKU2Y9yby4=\n-----END CERTIFICATE-----\n",
			keyCert:    "-----BEGIN CERTIFICATE-----\nMIICVTCCAT2gAwIBAgIQAU4Yg7Qnw9FZgMBEaJ7ZMzANBgkqhkiG9w0BAQsFADAh\nMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0dGVzdGF0aW9uMCAXDTE2MDMxNDAwMDAw\nMFoYDzIwNTIwNDE3MDAwMDAwWjAlMSMwIQYDVQQDDBpZdWJpS2V5IFBJViBBdHRl\nc3RhdGlvbiA5YTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABATzM3sJuwemL2Ha\nHkGIzmCVjUMreNIVrRLOvnbZjoVflk1eab/iLUlKzk/2jXTu9TISRg2dhyXcutct\nvnqr66yjTjBMMBEGCisGAQQBgsQKAwMEAwUEAzAUBgorBgEEAYLECgMHBAYCBADw\nDxQwEAYKKwYBBAGCxAoDCAQCAgEwDwYKKwYBBAGCxAoDCQQBBDANBgkqhkiG9w0B\nAQsFAAOCAQEAFX0hL5gi/g4ZM7vCH5kDAtma7eBp0LpbCzR313GGyBR7pJFtuj2l\nbWU+V3SFRihXBTDb8q+uvyCBqgz1szdZzrpfjqNkhEPfPNabxjxJxVoe6Gdcn115\naduxfqqT2u+YIsERzaIIIisehLQkc/5zLkpocA6jbKBZnZWUBJIxuz4QmYTIf0O4\nHPE2o4JbAyGx/hRaqVvDgNeAz94ZFjb4Mp3RNbbdRUZB0ehrT/IGRJoHRu2HKFGM\nylRJL2kjKPoEc4XHbCu+MfmAIrQ4Xseg85zyI7ThhYvAzktdLHhQyfYr4wrrLCN3\noeTzmiqIHe9AataJXQ+mEQEEc9TNY23RFg==\n-----END CERTIFICATE-----\n",
			ok:         false,
		},
	}

	parseCert := func(cert string) (*x509.Certificate, error) {
		block, _ := pem.Decode([]byte(cert))
		if block == nil {
			t.Fatalf("decoding PEM cert, empty block")
		}
		return x509.ParseCertificate(block.Bytes)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deviceCert, err := parseCert(test.deviceCert)
			if err != nil {
				t.Fatalf("parsing device cert: %v", err)
			}

			keyCert, err := parseCert(test.keyCert)
			if err != nil {
				t.Fatalf("parsing key cert: %v", err)
			}

			_, err = Verify(deviceCert, keyCert)
			if (err == nil) != test.ok {
				t.Errorf("Verify returned %v, expected test outcome %v", err, test.ok)
			}
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
	if err != nil {
		t.Fatalf("ephemeral key: %v", err)
	}
	return key
}
