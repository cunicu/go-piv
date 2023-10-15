// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import "testing"

// TestDerivePINPolicy checks that YubiKeys with version >= 5.3.0 use the
// KeyInfo method to determine the pin policy, instead of the attestation
// certificate.
func TestPINPolicy(t *testing.T) {
	func() {
		yk, closeCard := newTestYubiKey(t)
		defer closeCard()

		testRequiresVersion(t, yk, 5, 3, 0)

		if err := yk.Reset(); err != nil {
			t.Fatalf("resetting key: %v", err)
		}
	}()

	yk, closeCard := newTestYubiKey(t)
	defer closeCard()

	// for imported keys, using the attestation certificate to derive the PIN
	// policy fails. So we check that pinPolicy succeeds with imported keys.
	priv := ephemeralKey(t, AlgorithmEC256)
	if err := yk.SetPrivateKeyInsecure(DefaultManagementKey, SlotAuthentication, priv, Key{
		Algorithm:   AlgorithmEC256,
		PINPolicy:   PINPolicyNever,
		TouchPolicy: TouchPolicyNever,
	}); err != nil {
		t.Fatalf("import key: %v", err)
	}
	if got, err := pinPolicy(yk, SlotAuthentication); err != nil || got != PINPolicyNever {
		t.Fatalf("pinPolicy() = %v, %v, want %v, <nil>", got, err, PINPolicyNever)
	}
}
