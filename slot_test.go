// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//nolint:gocognit
func TestSlots(t *testing.T) {
	c, closeCard := newTestCard(t)

	err := c.Reset()
	require.NoError(t, err, "Failed to reset applet")

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
				_, err := c.Attest(test.slot)
				assert.ErrorIs(t, err, ErrNotFound)
			}

			k := Key{
				Algorithm:   AlgorithmEC256,
				PINPolicy:   PINPolicyNever,
				TouchPolicy: TouchPolicyNever,
			}
			pub, err := c.GenerateKey(DefaultManagementKey, test.slot, k)
			require.NoError(t, err, "Failed to generate key on slot")

			if supportsAttestation(c) {
				_, err := c.Attest(test.slot)
				assert.NoError(t, err, "Failed to attest")
			}

			priv, err := c.PrivateKey(test.slot, pub, KeyAuth{PIN: DefaultPIN})
			require.NoError(t, err, "Failed to get private key")

			tmpl := &x509.Certificate{
				Subject:      pkix.Name{CommonName: "my-client"},
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(time.Hour),
				KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
			require.NoError(t, err, "Failed to sign self-signed certificate")

			cert, err := x509.ParseCertificate(raw)
			require.NoError(t, err, "Failed to parse certificate")

			_, err = c.Certificate(test.slot)
			assert.ErrorIs(t, err, ErrNotFound)

			err = c.SetCertificate(DefaultManagementKey, test.slot, cert)
			require.NoError(t, err, "Failed to set certificate")

			got, err := c.Certificate(test.slot)
			require.NoError(t, err, "Failed to get certificate")

			assert.Equal(t, raw, got.Raw, "Certificate from slot didn't match the certificate written")
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
			gotSlot, gotOk := parseSlot(test.cn)
			assert.Equal(t, test.ok, gotOk)
			assert.Equal(t, test.slot, gotSlot, "Returned slot %+v did not match expected %+v", gotSlot, test.slot)
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
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotSlot, gotOk := RetiredKeyManagementSlot(test.key)
			assert.Equal(t, test.wantSlot, gotSlot)
			assert.Equal(t, test.wantOk, gotOk)
		})
	}
}
