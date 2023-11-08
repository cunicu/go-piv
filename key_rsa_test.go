// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignRSA(t *testing.T) {
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

				data := sha256.Sum256([]byte("hello"))
				priv, err := c.PrivateKey(slot, pub, KeyAuth{})
				require.NoError(t, err, "Failed to get private key")

				s, ok := priv.(crypto.Signer)
				require.True(t, ok, "Private key didn't implement crypto.Signer")

				out, err := s.Sign(c.Rand, data[:], crypto.SHA256)
				require.NoError(t, err, "Failed to sign failed")

				err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, data[:], out)
				assert.NoError(t, err, "Failed to verify signature")
			})
		})
	}
}

func TestSignRSAPSS(t *testing.T) {
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

				data := sha256.Sum256([]byte("hello"))
				priv, err := c.PrivateKey(slot, pub, KeyAuth{})
				require.NoError(t, err, "Failed to get private key")

				s, ok := priv.(crypto.Signer)
				require.True(t, ok, "Private key didn't implement crypto.Signer")

				opt := &rsa.PSSOptions{Hash: crypto.SHA256}
				out, err := s.Sign(c.Rand, data[:], opt)
				require.NoError(t, err, "Failed to sign failed")

				err = rsa.VerifyPSS(pub, crypto.SHA256, data[:], out, opt)
				assert.NoError(t, err, "Failed to verify signature")
			})
		})
	}
}

func TestSetRSAPrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		bits    int
		slot    Slot
		wantErr error
	}{
		{
			name:    "RSA/1024",
			bits:    1024,
			slot:    SlotSignature,
			wantErr: nil,
		},
		{
			name:    "RSA/2048",
			bits:    2048,
			slot:    SlotCardAuthentication,
			wantErr: nil,
		},
		{
			name:    "RSA/4096",
			bits:    4096,
			slot:    SlotAuthentication,
			wantErr: errUnsupportedKeySize,
		},
		{
			name:    "RSA/512",
			bits:    512,
			slot:    SlotKeyManagement,
			wantErr: errUnsupportedKeySize,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withCard(t, false, false, nil, func(t *testing.T, c *Card) {
				key := testKey(t, AlgTypeRSA, test.bits)
				generated, ok := key.(*rsa.PrivateKey)
				require.True(t, ok)

				err := c.SetPrivateKeyInsecure(DefaultManagementKey, test.slot, generated, Key{
					PINPolicy:   PINPolicyNever,
					TouchPolicy: TouchPolicyNever,
				})
				require.ErrorIs(t, err, test.wantErr)
				if err != nil {
					return
				}

				priv, err := c.PrivateKey(test.slot, &generated.PublicKey, KeyAuth{})
				require.NoError(t, err, "Failed to get private key")

				data := []byte("Test data that we will encrypt")

				// Encrypt the data using our generated key
				encrypted, err := rsa.EncryptPKCS1v15(c.Rand, &generated.PublicKey, data)
				require.NoError(t, err, "Failed to encrypt data")

				deviceDecrypter, ok := priv.(crypto.Decrypter)
				require.True(t, ok, "Private key is not a crypto.Decrypter")

				// Decrypt the data on the device
				decrypted, err := deviceDecrypter.Decrypt(c.Rand, encrypted, nil)
				require.NoError(t, err, "Failed to decrypt data")

				require.Equal(t, data, decrypted, "Decrypted data is different to the source data")
			})
		})
	}
}

func TestTLS13(t *testing.T) {
	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		slot := SlotAuthentication
		key := Key{
			Algorithm:   AlgRSA1024,
			TouchPolicy: TouchPolicyNever,
			PINPolicy:   PINPolicyNever,
		}

		pub, err := c.GenerateKey(DefaultManagementKey, slot, key)
		require.NoError(t, err, "Failed to generate key")

		priv, err := c.PrivateKey(slot, pub, KeyAuth{})
		require.NoError(t, err, "Failed to get private key")

		tmpl := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "test",
			},
			SerialNumber: big.NewInt(100),
			DNSNames:     []string{"example.com"},
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth,
			},
		}

		// Certificate must be deterministic for
		// reproducible tests
		tmpl.NotBefore, _ = time.Parse(time.DateOnly, "2020-01-01")
		tmpl.NotAfter, _ = time.Parse(time.DateOnly, "2030-01-01")

		rawCert, err := x509.CreateCertificate(c.Rand, tmpl, tmpl, pub, priv)
		require.NoError(t, err, "Failed to create certificate")

		x509Cert, err := x509.ParseCertificate(rawCert)
		require.NoError(t, err, "Failed to parse cert")

		cert := tls.Certificate{
			Certificate: [][]byte{rawCert},
			PrivateKey:  priv,
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.PSSWithSHA256,
			},
		}
		pool := x509.NewCertPool()
		pool.AddCert(x509Cert)

		cliConf := &tls.Config{
			Rand:         c.Rand,
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			ServerName:   "example.com",
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
		}
		srvConf := &tls.Config{
			Rand:         c.Rand,
			Certificates: []tls.Certificate{cert},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
		}

		srv, err := tls.Listen("tcp", "127.0.0.1:0", srvConf)
		require.NoError(t, err, "Failed to create TLS listener")

		defer srv.Close()

		errCh := make(chan error, 2)

		want := []byte("hello, world")

		go func() {
			conn, err := srv.Accept()
			if err != nil {
				errCh <- fmt.Errorf("failed to accept connection: %w", err)
				return
			}
			defer conn.Close()

			got := make([]byte, len(want))
			if _, err := io.ReadFull(conn, got); err != nil {
				errCh <- fmt.Errorf("failed to read data: %w", err)
				return
			}
			if !bytes.Equal(want, got) {
				errCh <- fmt.Errorf("%w: got=%s, want=%s", errUnexpectedValue, got, want)
				return
			}
			errCh <- nil
		}()

		go func() {
			conn, err := tls.Dial("tcp", srv.Addr().String(), cliConf)
			if err != nil {
				errCh <- fmt.Errorf("failed to dial: %w", err)
				return
			}
			defer conn.Close()

			if v := conn.ConnectionState().Version; v != tls.VersionTLS13 {
				errCh <- fmt.Errorf("%w: got=0x%x, want=0x%x", errUnexpectedVersion, v, tls.VersionTLS13)
				return
			}

			if _, err := conn.Write(want); err != nil {
				errCh <- fmt.Errorf("failed to write: %w", err)
				return
			}
			errCh <- nil
		}()

		for i := 0; i < 2; i++ {
			require.NoError(t, <-errCh)
		}
	})
}
