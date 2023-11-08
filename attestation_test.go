// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttestation(t *testing.T) {
	withCard(t, false, false, SupportsAttestation, func(t *testing.T, c *Card) {
		key := Key{
			Algorithm:   AlgECCP256,
			PINPolicy:   PINPolicyNever,
			TouchPolicy: TouchPolicyNever,
		}

		certAttest, err := c.AttestationCertificate()
		require.NoError(t, err, "Failed to get attestation certificate")

		_, err = c.GenerateKey(DefaultManagementKey, SlotAuthentication, key)
		require.NoError(t, err, "Failed to generate key")

		certAuth, err := c.Attest(SlotAuthentication)
		require.NoError(t, err, "Failed to attest key")

		a, err := Verify(certAttest, certAuth)
		require.NoError(t, err, "Failed to verify attestation")

		serial, err := c.Serial()
		assert.NoError(t, err, "Failed to get serial number")
		assert.Equal(t, serial, a.Serial, "Mismatching attestation serial got=%d, wanted=%d", a.Serial, serial)
		assert.Equal(t, key.PINPolicy, a.PINPolicy, "Mismatching attestation pin policy got=0x%x, wanted=0x%x", a.TouchPolicy, key.PINPolicy)
		assert.Equal(t, key.TouchPolicy, a.TouchPolicy, "Mismatching attestation touch policy got=0x%x, wanted=0x%x", a.TouchPolicy, key.TouchPolicy)
		assert.Equal(t, c.Version(), a.Version, "Mismatching attestation version got=%#v, wanted=%#v", a.Version, c.Version())
		assert.Equal(t, SlotAuthentication, a.Slot, "Mismatching attested slot got=%v, wanted=%v", a.Slot, SlotAuthentication)
		assert.Equal(t, "9a", a.Slot.String(), "Mismatching attested slot name got=%s, wanted=%s", a.Slot.String(), "9a")
	})
}
