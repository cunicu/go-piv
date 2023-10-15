// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
)

func TestYubiKeyECDSASharedKey(t *testing.T) {
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()

	slot := SlotAuthentication

	key := Key{
		Algorithm:   AlgorithmEC256,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyNever,
	}
	pubKey, err := yk.GenerateKey(DefaultManagementKey, slot, key)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not an ecdsa key")
	}
	priv, err := yk.PrivateKey(slot, pub, KeyAuth{})
	if err != nil {
		t.Fatalf("getting private key: %v", err)
	}
	privECDSA, ok := priv.(*ECDSAPrivateKey)
	if !ok {
		t.Fatalf("expected private key to be ECDSA private key")
	}

	t.Run("good", func(t *testing.T) {
		eph, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("cannot generate key: %v", err)
		}
		mult, _ := pub.ScalarMult(pub.X, pub.Y, eph.D.Bytes())
		secret1 := mult.Bytes()

		secret2, err := privECDSA.SharedKey(&eph.PublicKey)
		if err != nil {
			t.Fatalf("key agreement failed: %v", err)
		}
		if !bytes.Equal(secret1, secret2) {
			t.Errorf("key agreement didn't match")
		}
	})

	t.Run("bad", func(t *testing.T) {
		t.Run("size", func(t *testing.T) {
			eph, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatalf("cannot generate key: %v", err)
			}
			_, err = privECDSA.SharedKey(&eph.PublicKey)
			if !errors.Is(err, errMismatchingAlgorithms) {
				t.Fatalf("unexpected error value: wanted errMismatchingAlgorithms: %v", err)
			}
		})
	})
}

func TestSetECDSAPrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		curve   elliptic.Curve
		slot    Slot
		wantErr error
	}{
		{
			name:    "ecdsa P256",
			curve:   elliptic.P256(),
			slot:    SlotSignature,
			wantErr: nil,
		},
		{
			name:    "ecdsa P384",
			curve:   elliptic.P384(),
			slot:    SlotCardAuthentication,
			wantErr: nil,
		},
		{
			name:    "ecdsa P224",
			curve:   elliptic.P224(),
			slot:    SlotAuthentication,
			wantErr: unsupportedCurveError{curve: 224},
		},
		{
			name:    "ecdsa P521",
			curve:   elliptic.P521(),
			slot:    SlotKeyManagement,
			wantErr: unsupportedCurveError{curve: 521},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yk, closeCard := newTestYubiKey(t)
			defer closeCard()

			generated, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("generating private key: %v", err)
			}

			err = yk.SetPrivateKeyInsecure(DefaultManagementKey, tt.slot, generated, Key{
				PINPolicy:   PINPolicyNever,
				TouchPolicy: TouchPolicyNever,
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("SetPrivateKeyInsecure(): wantErr=%v, got err=%v", tt.wantErr, err)
			}
			if err != nil {
				return
			}

			priv, err := yk.PrivateKey(tt.slot, &generated.PublicKey, KeyAuth{})
			if err != nil {
				t.Fatalf("getting private key: %v", err)
			}

			deviceSigner, ok := priv.(crypto.Signer)
			if !ok {
				t.Fatal("Private key is not a crypto.Signer")
			}

			hash := []byte("Test data to sign")
			// Sign the data on the device
			sig, err := deviceSigner.Sign(rand.Reader, hash, nil)
			if err != nil {
				t.Fatalf("signing data: %v", err)
			}

			// Verify the signature using the generated key
			if !ecdsa.VerifyASN1(&generated.PublicKey, hash, sig) {
				t.Fatal("Failed to verify signed data")
			}
		})
	}
}

func TestYubiKeySignECDSA(t *testing.T) {
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()

	if err := yk.Reset(); err != nil {
		t.Fatalf("reset yubikey: %v", err)
	}

	slot := SlotAuthentication

	key := Key{
		Algorithm:   AlgorithmEC256,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyNever,
	}
	pubKey, err := yk.GenerateKey(DefaultManagementKey, slot, key)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not an ecdsa key")
	}
	data := sha256.Sum256([]byte("hello"))
	priv, err := yk.PrivateKey(slot, pub, KeyAuth{})
	if err != nil {
		t.Fatalf("getting private key: %v", err)
	}
	s, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("expected private key to implement crypto.Signer")
	}
	out, err := s.Sign(rand.Reader, data[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(out, &sig); err != nil {
		t.Fatalf("unmarshaling signature: %v", err)
	}
	if !ecdsa.Verify(pub, data[:], sig.R, sig.S) {
		t.Errorf("signature didn't match")
	}
}
