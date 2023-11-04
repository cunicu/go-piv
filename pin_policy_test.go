// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDerivePINPolicy checks that YubiKeys with version >= 5.3.0 use the
// KeyInfo method to determine the pin policy, instead of the attestation
// certificate.
func TestPINPolicy(t *testing.T) {
	func() {
		c, closeCard := newTestCard(t)
		defer closeCard()

		testRequiresVersion(t, c, 5, 3, 0)

		err := c.Reset()
		require.NoError(t, err, "Failed to reset applet")
	}()

	c, closeCard := newTestCard(t)
	defer closeCard()

	// for imported keys, using the attestation certificate to derive the PIN
	// policy fails. So we check that pinPolicy succeeds with imported keys.
	priv := ephemeralKey(t, AlgorithmEC256)

	err := c.SetPrivateKeyInsecure(DefaultManagementKey, SlotAuthentication, priv, Key{
		Algorithm:   AlgorithmEC256,
		PINPolicy:   PINPolicyNever,
		TouchPolicy: TouchPolicyNever,
	})
	require.NoError(t, err, "Failed to import key")

	got, err := pinPolicy(c, SlotAuthentication)
	require.NoError(t, err)
	require.Equal(t, PINPolicyNever, got)
}
