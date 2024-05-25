// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetadata(t *testing.T) {
	tests := []struct {
		name      string
		slot      Slot
		policy    Key
		importKey bool
	}{
		{
			"EC/P256/Generated",
			SlotAuthentication,
			Key{AlgECCP256, PINPolicyNever, TouchPolicyNever},
			false,
		},
		{
			"EC/P384/Generated",
			SlotAuthentication,
			Key{AlgECCP384, PINPolicyNever, TouchPolicyNever},
			false,
		},
		{
			"RSA/1024/Generated",
			SlotAuthentication,
			Key{AlgRSA1024, PINPolicyNever, TouchPolicyNever},
			false,
		},
		{
			"RSA/2048/Generated",
			SlotAuthentication,
			Key{AlgRSA2048, PINPolicyNever, TouchPolicyNever},
			false,
		},
		{
			"RSA/3072/Generated",
			SlotAuthentication,
			Key{AlgRSA3072, PINPolicyNever, TouchPolicyNever},
			false,
		},
		{
			"RSA/4096/Generated",
			SlotAuthentication,
			Key{AlgRSA4096, PINPolicyNever, TouchPolicyNever},
			false,
		},
		{
			"EC/P256/Imported",
			SlotAuthentication,
			Key{AlgECCP256, PINPolicyNever, TouchPolicyNever},
			true,
		},
		{
			"EC/P384/Imported",
			SlotAuthentication,
			Key{AlgECCP384, PINPolicyNever, TouchPolicyNever},
			true,
		},
		{
			"RSA/1024/Imported",
			SlotAuthentication,
			Key{AlgRSA1024, PINPolicyNever, TouchPolicyNever},
			true,
		},
		{
			"RSA/2048/Imported",
			SlotAuthentication,
			Key{AlgRSA2048, PINPolicyNever, TouchPolicyNever},
			true,
		},
		{
			"RSA/3072/Imported",
			SlotAuthentication,
			Key{AlgRSA3072, PINPolicyNever, TouchPolicyNever},
			true,
		},
		{
			"RSA/4096/Imported",
			SlotAuthentication,
			Key{AlgRSA4096, PINPolicyNever, TouchPolicyNever},
			true,
		},
		{
			"PINPolicy/Once",
			SlotAuthentication,
			Key{AlgECCP256, PINPolicyOnce, TouchPolicyNever},
			false,
		},
		{
			"PINPolicy/Always",
			SlotAuthentication,
			Key{AlgECCP256, PINPolicyAlways, TouchPolicyNever},
			false,
		},
		{
			"TouchPolicy/Always",
			SlotAuthentication,
			Key{AlgECCP256, PINPolicyNever, TouchPolicyAlways},
			false,
		},
		{
			"TouchPolicy/Cached",
			SlotAuthentication,
			Key{AlgECCP256, PINPolicyNever, TouchPolicyCached},
			false,
		},
		{
			"SlotSignature",
			SlotSignature,
			Key{AlgECCP256, PINPolicyNever, TouchPolicyCached},
			false,
		},
		{
			"SlotCardAuthentication",
			SlotCardAuthentication,
			Key{AlgECCP256, PINPolicyNever, TouchPolicyCached},
			false,
		},
		{
			"SlotKeyManagement",
			SlotKeyManagement,
			Key{AlgECCP256, PINPolicyNever, TouchPolicyCached},
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withCard(t, true, false, SupportsMetadata, func(t *testing.T, c *Card) {
				want := &Metadata{
					Algorithm:   test.policy.Algorithm,
					PINPolicy:   test.policy.PINPolicy,
					TouchPolicy: test.policy.TouchPolicy,
				}

				if test.importKey {
					key := testKey(t, test.policy.Algorithm.algType(), test.policy.Algorithm.bits())

					err := c.SetPrivateKeyInsecure(DefaultManagementKey, test.slot, key, test.policy)
					require.NoError(t, err, "importing key")

					want.Origin = OriginImported
					want.PublicKey = key.Public()
				} else {
					pub, err := c.GenerateKey(DefaultManagementKey, test.slot, test.policy)
					require.NoError(t, err, "Failed to generate key")

					want.Origin = OriginGenerated
					want.PublicKey = pub
				}

				got, err := c.Metadata(test.slot)
				require.NoError(t, err, "Failed to get key metadata")
				assert.Equal(t, want, got)
			})
		})
	}
}
