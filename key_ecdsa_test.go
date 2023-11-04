// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestECDSASharedKey(t *testing.T) {
	c, closeCard := newTestCard(t)
	defer closeCard()

	slot := SlotAuthentication

	key := Key{
		Algorithm:   AlgorithmEC256,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyNever,
	}
	pubKey, err := c.GenerateKey(DefaultManagementKey, slot, key)
	require.NoError(t, err, "Failed to generate key")

	pub, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok, "Public key is not an ECDSA key")

	priv, err := c.PrivateKey(slot, pub, KeyAuth{})
	require.NoError(t, err, "Failed to get private key")

	privECDSA, ok := priv.(*ECDSAPrivateKey)
	require.True(t, ok, "Expected private key to be ECDSA private key")

	t.Run("good", func(t *testing.T) {
		eph, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, "Failed to generate key")

		mult, _ := pub.ScalarMult(pub.X, pub.Y, eph.D.Bytes())
		secret1 := mult.Bytes()

		secret2, err := privECDSA.SharedKey(&eph.PublicKey)
		require.NoError(t, err, "Key agreement failed")

		assert.Equal(t, secret1, secret2, "Key agreement didn't match")
	})

	t.Run("bad", func(t *testing.T) {
		t.Run("size", func(t *testing.T) {
			eph, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			require.NoError(t, err, "Failed to generate key")

			_, err = privECDSA.SharedKey(&eph.PublicKey)
			require.ErrorIs(t, err, errMismatchingAlgorithms)
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
			name:    "ECDSA P256",
			curve:   elliptic.P256(),
			slot:    SlotSignature,
			wantErr: nil,
		},
		{
			name:    "ECDSA P384",
			curve:   elliptic.P384(),
			slot:    SlotCardAuthentication,
			wantErr: nil,
		},
		{
			name:    "ECDSA P224",
			curve:   elliptic.P224(),
			slot:    SlotAuthentication,
			wantErr: unsupportedCurveError{curve: 224},
		},
		{
			name:    "ECDSA P521",
			curve:   elliptic.P521(),
			slot:    SlotKeyManagement,
			wantErr: unsupportedCurveError{curve: 521},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, closeCard := newTestCard(t)
			defer closeCard()

			generated, err := ecdsa.GenerateKey(test.curve, rand.Reader)
			require.NoError(t, err, "Failed to generate private key")

			err = c.SetPrivateKeyInsecure(DefaultManagementKey, test.slot, generated, Key{
				PINPolicy:   PINPolicyNever,
				TouchPolicy: TouchPolicyNever,
			})
			require.ErrorIs(t, err, test.wantErr)
			if err != nil {
				return
			}

			priv, err := c.PrivateKey(test.slot, &generated.PublicKey, KeyAuth{})
			require.NoError(t, err, "Failed to getting private key")

			deviceSigner, ok := priv.(crypto.Signer)
			require.True(t, ok, "Private key is not a crypto.Signer")

			hash := []byte("Test data to sign")
			// Sign the data on the device
			sig, err := deviceSigner.Sign(rand.Reader, hash, nil)
			require.NoError(t, err, "Failed to sign data")

			// Verify the signature using the generated key
			ok = ecdsa.VerifyASN1(&generated.PublicKey, hash, sig)
			require.True(t, ok, "Failed to verify signed data")
		})
	}
}

func TestSignECDSA(t *testing.T) {
	c, closeCard := newTestCard(t)
	defer closeCard()

	err := c.Reset()
	require.NoError(t, err, "Failed to reset applet")

	slot := SlotAuthentication

	key := Key{
		Algorithm:   AlgorithmEC256,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyNever,
	}
	pubKey, err := c.GenerateKey(DefaultManagementKey, slot, key)
	require.NoError(t, err, "Failed to generate key")

	pub, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok, "public key is not an ecdsa key")

	data := sha256.Sum256([]byte("hello"))
	priv, err := c.PrivateKey(slot, pub, KeyAuth{})
	require.NoError(t, err, "Failed to gett private key")

	s, ok := priv.(crypto.Signer)
	require.True(t, ok, "expected private key to implement crypto.Signer")

	out, err := s.Sign(rand.Reader, data[:], crypto.SHA256)
	require.NoError(t, err, "Failed to sign")

	var sig struct {
		R, S *big.Int
	}
	_, err = asn1.Unmarshal(out, &sig)
	require.NoError(t, err, "Failed to unmarshal signature")

	verified := ecdsa.Verify(pub, data[:], sig.R, sig.S)
	assert.True(t, verified, "Signature didn't match")
}
