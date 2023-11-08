// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPINPolicy checks that YubiKeys with version >= 5.3.0 use the
// Metadata method to determine the PIN policy, instead of the attestation
// certificate.
func TestPINPolicy(t *testing.T) {
	withCard(t, true, false, SupportsMetadata, func(t *testing.T, c *Card) {
		// for imported keys, using the attestation certificate to derive the PIN
		// policy fails. So we check that pinPolicy succeeds with imported keys.
		priv := testKey(t, AlgTypeECCP, 256)

		err := c.SetPrivateKeyInsecure(DefaultManagementKey, SlotAuthentication, priv, Key{
			Algorithm:   AlgECCP256,
			PINPolicy:   PINPolicyNever,
			TouchPolicy: TouchPolicyNever,
		})
		require.NoError(t, err, "Failed to import key")

		got, err := pinPolicy(c, SlotAuthentication)
		require.NoError(t, err)
		require.Equal(t, PINPolicyNever, got)
	})
}
