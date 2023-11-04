// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyInfo(t *testing.T) {
	func() {
		c, closeCard := newTestCard(t)
		defer closeCard()

		testRequiresVersion(t, c, 5, 3, 0)

		err := c.Reset()
		require.NoError(t, err, "Failed to reset applet")
	}()

	tests := []struct {
		name      string
		slot      Slot
		importKey privateKey
		policy    Key
	}{
		{
			"Generated ec_256",
			SlotAuthentication,
			nil,
			Key{AlgorithmEC256, PINPolicyNever, TouchPolicyNever},
		},
		{
			"Generated ec_384",
			SlotAuthentication,
			nil,
			Key{AlgorithmEC384, PINPolicyNever, TouchPolicyNever},
		},
		{
			"Generated rsa_1024",
			SlotAuthentication,
			nil,
			Key{AlgorithmRSA1024, PINPolicyNever, TouchPolicyNever},
		},
		{
			"Generated rsa_2048",
			SlotAuthentication,
			nil,
			Key{AlgorithmRSA2048, PINPolicyNever, TouchPolicyNever},
		},
		{
			"Imported ec_256",
			SlotAuthentication,
			ephemeralKey(t, AlgorithmEC256),
			Key{AlgorithmEC256, PINPolicyNever, TouchPolicyNever},
		},
		{
			"Imported ec_384",
			SlotAuthentication,
			ephemeralKey(t, AlgorithmEC384),
			Key{AlgorithmEC384, PINPolicyNever, TouchPolicyNever},
		},
		{
			"Imported rsa_1024",
			SlotAuthentication,
			ephemeralKey(t, AlgorithmRSA1024),
			Key{AlgorithmRSA1024, PINPolicyNever, TouchPolicyNever},
		},
		{
			"Imported rsa_2048",
			SlotAuthentication,
			ephemeralKey(t, AlgorithmRSA2048),
			Key{AlgorithmRSA2048, PINPolicyNever, TouchPolicyNever},
		},
		{
			"PINPolicyOnce",
			SlotAuthentication,
			nil,
			Key{AlgorithmEC256, PINPolicyOnce, TouchPolicyNever},
		},
		{
			"PINPolicyAlways",
			SlotAuthentication,
			nil,
			Key{AlgorithmEC256, PINPolicyAlways, TouchPolicyNever},
		},
		{
			"TouchPolicyAlways",
			SlotAuthentication,
			nil,
			Key{AlgorithmEC256, PINPolicyNever, TouchPolicyAlways},
		},
		{
			"TouchPolicyCached",
			SlotAuthentication,
			nil,
			Key{AlgorithmEC256, PINPolicyNever, TouchPolicyCached},
		},
		{
			"SlotSignature",
			SlotSignature,
			nil,
			Key{AlgorithmEC256, PINPolicyNever, TouchPolicyCached},
		},
		{
			"SlotCardAuthentication",
			SlotCardAuthentication,
			nil,
			Key{AlgorithmEC256, PINPolicyNever, TouchPolicyCached},
		},
		{
			"SlotKeyManagement",
			SlotKeyManagement,
			nil,
			Key{AlgorithmEC256, PINPolicyNever, TouchPolicyCached},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, closeCard := newTestCard(t)
			defer closeCard()

			want := KeyInfo{
				Algorithm:   test.policy.Algorithm,
				PINPolicy:   test.policy.PINPolicy,
				TouchPolicy: test.policy.TouchPolicy,
			}

			if test.importKey == nil {
				pub, err := c.GenerateKey(DefaultManagementKey, test.slot, test.policy)
				require.NoError(t, err, "Failed to generate key")

				want.Origin = OriginGenerated
				want.PublicKey = pub
			} else {
				err := c.SetPrivateKeyInsecure(DefaultManagementKey, test.slot, test.importKey, test.policy)
				require.NoError(t, err, "importing key")

				want.Origin = OriginImported
				want.PublicKey = test.importKey.Public()
			}

			got, err := c.KeyInfo(test.slot)
			require.NoError(t, err, "Failed to KeyInfo()")
			assert.Equal(t, want, got, "KeyInfo() = %#v, want %#v", got, want)
		})
	}
}
