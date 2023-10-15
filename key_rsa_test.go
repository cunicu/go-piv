// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"
)

func TestYubiKeySignRSA(t *testing.T) {
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
			data := sha256.Sum256([]byte("hello"))
			priv, err := yk.PrivateKey(slot, pub, KeyAuth{})
			if err != nil {
				t.Fatalf("getting private key: %v", err)
			}
			s, ok := priv.(crypto.Signer)
			if !ok {
				t.Fatalf("private key didn't implement crypto.Signer")
			}
			out, err := s.Sign(rand.Reader, data[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("signing failed: %v", err)
			}
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, data[:], out); err != nil {
				t.Errorf("failed to verify signature: %v", err)
			}
		})
	}
}

func TestYubiKeySignRSAPSS(t *testing.T) {
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
			data := sha256.Sum256([]byte("hello"))
			priv, err := yk.PrivateKey(slot, pub, KeyAuth{})
			if err != nil {
				t.Fatalf("getting private key: %v", err)
			}
			s, ok := priv.(crypto.Signer)
			if !ok {
				t.Fatalf("private key didn't implement crypto.Signer")
			}

			opt := &rsa.PSSOptions{Hash: crypto.SHA256}
			out, err := s.Sign(rand.Reader, data[:], opt)
			if err != nil {
				t.Fatalf("signing failed: %v", err)
			}
			if err := rsa.VerifyPSS(pub, crypto.SHA256, data[:], out, opt); err != nil {
				t.Errorf("failed to verify signature: %v", err)
			}
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
			name:    "rsa 1024",
			bits:    1024,
			slot:    SlotSignature,
			wantErr: nil,
		},
		{
			name:    "rsa 2048",
			bits:    2048,
			slot:    SlotCardAuthentication,
			wantErr: nil,
		},
		{
			name:    "rsa 4096",
			bits:    4096,
			slot:    SlotAuthentication,
			wantErr: errUnsupportedKeySize,
		},
		{
			name:    "rsa 512",
			bits:    512,
			slot:    SlotKeyManagement,
			wantErr: errUnsupportedKeySize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yk, closeCard := newTestYubiKey(t)
			defer closeCard()

			generated, err := rsa.GenerateKey(rand.Reader, tt.bits)
			if err != nil {
				t.Fatalf("generating private key: %v", err)
			}

			if err = yk.SetPrivateKeyInsecure(DefaultManagementKey, tt.slot, generated, Key{
				PINPolicy:   PINPolicyNever,
				TouchPolicy: TouchPolicyNever,
			}); !errors.Is(err, tt.wantErr) {
				t.Fatalf("SetPrivateKeyInsecure(): wantErr=%v, got err=%v", tt.wantErr, err)
			}
			if err != nil {
				return
			}

			priv, err := yk.PrivateKey(tt.slot, &generated.PublicKey, KeyAuth{})
			if err != nil {
				t.Fatalf("getting private key: %v", err)
			}

			data := []byte("Test data that we will encrypt")

			// Encrypt the data using our generated key
			encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &generated.PublicKey, data)
			if err != nil {
				t.Fatalf("encrypting data: %v", err)
			}

			deviceDecrypter, ok := priv.(crypto.Decrypter)
			if !ok {
				t.Fatalf("Pivate key is not a crypto.Decrypter")
			}

			// Decrypt the data on the device
			decrypted, err := deviceDecrypter.Decrypt(rand.Reader, encrypted, nil)
			if err != nil {
				t.Fatalf("decrypting data: %v", err)
			}

			if !bytes.Equal(data, decrypted) {
				t.Fatalf("decrypted data is different to the source data")
			}
		})
	}
}

func TestTLS13(t *testing.T) {
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()
	slot := SlotAuthentication
	key := Key{
		Algorithm:   AlgorithmRSA1024,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyNever,
	}
	pub, err := yk.GenerateKey(DefaultManagementKey, slot, key)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	priv, err := yk.PrivateKey(slot, pub, KeyAuth{})
	if err != nil {
		t.Fatalf("getting private key: %v", err)
	}

	tmpl := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "test"},
		SerialNumber: big.NewInt(100),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com"},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}

	rawCert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	x509Cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		t.Fatalf("parsing cert: %v", err)
	}
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
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   "example.com",
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	srvConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	srv, err := tls.Listen("tcp", "127.0.0.1:0", srvConf)
	if err != nil {
		t.Fatalf("creating tls listener: %v", err)
	}
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
		if err := <-errCh; err != nil {
			t.Fatalf("%v", err)
		}
	}
}
