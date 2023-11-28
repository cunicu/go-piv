// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestECCPSharedKey(t *testing.T) {
	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		slot := SlotAuthentication

		key := Key{
			Algorithm:   AlgECCP256,
			TouchPolicy: TouchPolicyNever,
			PINPolicy:   PINPolicyNever,
		}
		pubKey, err := c.GenerateKey(DefaultManagementKey, slot, key)
		require.NoError(t, err, "Failed to generate key")

		pub, ok := pubKey.(*ecdsa.PublicKey)
		require.True(t, ok, "Public key is not an EC key")

		priv, err := c.PrivateKey(slot, pub, KeyAuth{})
		require.NoError(t, err, "Failed to get private key")

		privECCP, ok := priv.(*ECPPPrivateKey)
		require.True(t, ok, "Expected private key to be EC private key")

		t.Run("good", func(t *testing.T) {
			key, ok := testKey(t, AlgTypeECCP, 256).(*ecdsa.PrivateKey)
			require.True(t, ok)

			mult, _ := pub.ScalarMult(pub.X, pub.Y, key.D.Bytes())
			secret1 := mult.Bytes()

			secret2, err := privECCP.SharedKey(&key.PublicKey)
			require.NoError(t, err, "Key agreement failed")

			assert.Equal(t, secret1, secret2, "Key agreement didn't match")
		})

		t.Run("bad", func(t *testing.T) {
			t.Run("size", func(t *testing.T) {
				key, ok := testKey(t, AlgTypeECCP, 384).(*ecdsa.PrivateKey)
				require.True(t, ok)

				_, err = privECCP.SharedKey(&key.PublicKey)
				require.ErrorIs(t, err, errMismatchingAlgorithms)
			})
		})
	})
}

func TestSetECCPPrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		bits    int
		slot    Slot
		wantErr error
	}{
		{
			name:    "EC/P256",
			bits:    256,
			slot:    SlotSignature,
			wantErr: nil,
		},
		{
			name:    "EC/P384",
			bits:    384,
			slot:    SlotCardAuthentication,
			wantErr: nil,
		},
		{
			name:    "EC/P224",
			bits:    224,
			slot:    SlotAuthentication,
			wantErr: UnsupportedCurveError{curve: 224},
		},
		{
			name:    "EC/P521",
			bits:    521,
			slot:    SlotKeyManagement,
			wantErr: UnsupportedCurveError{curve: 521},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withCard(t, false, false, nil, func(t *testing.T, c *Card) {
				generated, ok := testKey(t, AlgTypeECCP, test.bits).(*ecdsa.PrivateKey)
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
				require.NoError(t, err, "Failed to getting private key")

				deviceSigner, ok := priv.(crypto.Signer)
				require.True(t, ok, "Private key is not a crypto.Signer")

				hash := []byte("Test data to sign")
				// Sign the data on the device
				sig, err := deviceSigner.Sign(c.Rand, hash, nil)
				require.NoError(t, err, "Failed to sign data")

				// Verify the signature using the generated key
				ok = ecdsa.VerifyASN1(&generated.PublicKey, hash, sig)
				require.True(t, ok, "Failed to verify signed data")
			})
		})
	}
}

func TestSignECCP(t *testing.T) {
	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		err := c.Reset()
		require.NoError(t, err, "Failed to reset applet")

		slot := SlotAuthentication

		key := Key{
			Algorithm:   AlgECCP256,
			TouchPolicy: TouchPolicyNever,
			PINPolicy:   PINPolicyNever,
		}
		pubKey, err := c.GenerateKey(DefaultManagementKey, slot, key)
		require.NoError(t, err, "Failed to generate key")

		pub, ok := pubKey.(*ecdsa.PublicKey)
		require.True(t, ok, "public key is not an EC key")

		data := sha256.Sum256([]byte("hello"))
		priv, err := c.PrivateKey(slot, pub, KeyAuth{})
		require.NoError(t, err, "Failed to get private key")

		s, ok := priv.(crypto.Signer)
		require.True(t, ok, "expected private key to implement crypto.Signer")

		out, err := s.Sign(c.Rand, data[:], crypto.SHA256)
		require.NoError(t, err, "Failed to sign")

		var sig struct {
			R, S *big.Int
		}
		_, err = asn1.Unmarshal(out, &sig)
		require.NoError(t, err, "Failed to unmarshal signature")

		verified := ecdsa.Verify(pub, data[:], sig.R, sig.S)
		assert.True(t, verified, "Signature didn't match")
	})
}
