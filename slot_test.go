// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

//nolint:gocognit
func TestSlots(t *testing.T) {
	c, closeCard := newTestCard(t)
	if err := c.Reset(); err != nil {
		t.Fatalf("resetting yubikey: %v", err)
	}
	closeCard()

	tests := []struct {
		name string
		slot Slot
	}{
		{"Authentication", SlotAuthentication},
		{"CardAuthentication", SlotCardAuthentication},
		{"KeyManagement", SlotKeyManagement},
		{"Signature", SlotSignature},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, closeCard := newTestCard(t)
			defer closeCard()

			if supportsAttestation(c) {
				if _, err := c.Attest(test.slot); err == nil || !errors.Is(err, ErrNotFound) {
					t.Errorf("attest: got=%v, want=ErrNotFound", err)
				}
			}

			k := Key{
				Algorithm:   AlgorithmEC256,
				PINPolicy:   PINPolicyNever,
				TouchPolicy: TouchPolicyNever,
			}
			pub, err := c.GenerateKey(DefaultManagementKey, test.slot, k)
			if err != nil {
				t.Fatalf("generating key on slot: %v", err)
			}

			if supportsAttestation(c) {
				if _, err := c.Attest(test.slot); err != nil {
					t.Errorf("attest: %v", err)
				}
			}

			priv, err := c.PrivateKey(test.slot, pub, KeyAuth{PIN: DefaultPIN})
			if err != nil {
				t.Fatalf("private key: %v", err)
			}

			tmpl := &x509.Certificate{
				Subject:      pkix.Name{CommonName: "my-client"},
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(time.Hour),
				KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
			if err != nil {
				t.Fatalf("signing self-signed certificate: %v", err)
			}
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				t.Fatalf("parse certificate: %v", err)
			}

			if _, err := c.Certificate(test.slot); err == nil || !errors.Is(err, ErrNotFound) {
				t.Errorf("get certificate, got err=%v, want=ErrNotFound", err)
			}
			if err := c.SetCertificate(DefaultManagementKey, test.slot, cert); err != nil {
				t.Fatalf("set certificate: %v", err)
			}
			got, err := c.Certificate(test.slot)
			if err != nil {
				t.Fatalf("get certifiate: %v", err)
			}
			if !bytes.Equal(got.Raw, raw) {
				t.Errorf("certificate from slot didn't match the certificate written")
			}
		})
	}
}

func TestParseSlot(t *testing.T) {
	tests := []struct {
		name string
		cn   string
		ok   bool
		slot Slot
	}{
		{
			name: "Missing Yubico PIV Prefix",
			cn:   "invalid",
			ok:   false,
			slot: Slot{},
		},
		{
			name: "Invalid Slot Name",
			cn:   yubikeySubjectCNPrefix + "xy",
			ok:   false,
			slot: Slot{},
		},
		{
			name: "Valid -- SlotAuthentication",
			cn:   yubikeySubjectCNPrefix + "9a",
			ok:   true,
			slot: SlotAuthentication,
		},
		{
			name: "Valid -- Retired Management Key",
			cn:   yubikeySubjectCNPrefix + "89",
			ok:   true,
			slot: retiredKeyManagementSlots[uint32(137)],
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			slot, ok := parseSlot(test.cn)

			if ok != test.ok {
				t.Errorf("ok status returned %v, expected %v", ok, test.ok)
			}

			if slot != test.slot {
				t.Errorf("returned slot %+v did not match expected %+v", slot, test.slot)
			}
		})
	}
}

func TestRetiredKeyManagementSlot(t *testing.T) {
	tests := []struct {
		name     string
		key      uint32
		wantSlot Slot
		wantOk   bool
	}{
		{
			name:     "Non-existent slot, before range",
			key:      0x0,
			wantSlot: Slot{},
			wantOk:   false,
		},
		{
			name:     "Non-existent slot, after range",
			key:      0x96,
			wantSlot: Slot{},
			wantOk:   false,
		},
		{
			name:     "First retired slot key",
			key:      0x82,
			wantSlot: Slot{0x82, 0x5fc10d},
			wantOk:   true,
		},
		{
			name:     "Last retired slot key",
			key:      0x95,
			wantSlot: Slot{0x95, 0x5fc120},
			wantOk:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSlot, gotOk := RetiredKeyManagementSlot(tt.key)
			if gotSlot != tt.wantSlot {
				t.Errorf("RetiredKeyManagementSlot() got=%v, want=%v", gotSlot, tt.wantSlot)
			}
			if gotOk != tt.wantOk {
				t.Errorf("RetiredKeyManagementSlot() got=%v, want=%v", gotOk, tt.wantOk)
			}
		})
	}
}
