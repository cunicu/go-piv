// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import "testing"

func supportsAttestation(yk *YubiKey) bool {
	return supportsVersion(yk.Version(), 4, 3, 0)
}

func TestYubiKeyAttestation(t *testing.T) {
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()
	key := Key{
		Algorithm:   AlgorithmEC256,
		PINPolicy:   PINPolicyNever,
		TouchPolicy: TouchPolicyNever,
	}

	testRequiresVersion(t, yk, 4, 3, 0)

	cert, err := yk.AttestationCertificate()
	if err != nil {
		t.Fatalf("getting attestation certificate: %v", err)
	}

	pub, err := yk.GenerateKey(DefaultManagementKey, SlotAuthentication, key)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_ = pub
	c, err := yk.Attest(SlotAuthentication)
	if err != nil {
		t.Fatalf("attesting key: %v", err)
	}
	a, err := Verify(cert, c)
	if err != nil {
		t.Fatalf("failed to verify attestation: %v", err)
	}
	serial, err := yk.Serial()
	if err != nil {
		t.Errorf("getting serial number: %v", err)
	} else if a.Serial != serial {
		t.Errorf("attestation serial got=%d, wanted=%d", a.Serial, serial)
	}

	if a.PINPolicy != key.PINPolicy {
		t.Errorf("attestation pin policy got=0x%x, wanted=0x%x", a.TouchPolicy, key.PINPolicy)
	}
	if a.TouchPolicy != key.TouchPolicy {
		t.Errorf("attestation touch policy got=0x%x, wanted=0x%x", a.TouchPolicy, key.TouchPolicy)
	}
	if a.Version != yk.Version() {
		t.Errorf("attestation version got=%#v, wanted=%#v", a.Version, yk.Version())
	}
	if a.Slot != SlotAuthentication {
		t.Errorf("attested slot got=%v, wanted=%v", a.Slot, SlotAuthentication)
	}
	if a.Slot.String() != "9a" {
		t.Errorf("attested slot name got=%s, wanted=%s", a.Slot.String(), "9a")
	}
}
