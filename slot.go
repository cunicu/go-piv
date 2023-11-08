// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"strconv"
	"strings"
)

func parseSlot(commonName string) (Slot, bool) {
	if !strings.HasPrefix(commonName, yubikeySubjectCNPrefix) {
		return Slot{}, false
	}

	slotName := strings.TrimPrefix(commonName, yubikeySubjectCNPrefix)
	key, err := strconv.ParseUint(slotName, 16, 32)
	if err != nil {
		return Slot{}, false
	}

	switch byte(key) {
	case SlotAuthentication.Key:
		return SlotAuthentication, true

	case SlotSignature.Key:
		return SlotSignature, true

	case SlotCardAuthentication.Key:
		return SlotCardAuthentication, true

	case SlotKeyManagement.Key:
		return SlotKeyManagement, true
	}

	return SlotRetiredKeyManagement(byte(key))
}

// Slot combinations pre-defined by this package.
//
// Object IDs are specified in NIST 800-73-4 section 4.3:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=30
//
// Key IDs are specified in NIST 800-73-4 section 5.1:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=32
//
//nolint:gochecknoglobals
var (
	SlotAuthentication     = Slot{keyAuthentication, doCertAuthentication}
	SlotSignature          = Slot{keySignature, doCertSignature}
	SlotCardAuthentication = Slot{keyCardAuthentication, doCertCardAuthentication}
	SlotKeyManagement      = Slot{keyKeyManagement, doCertKeyManagement}

	// YubiKey specific
	SlotAttestation = Slot{keyAttestation, doCertAttestation}
)

// SlotRetiredKeyManagement provides access to "retired" slots. Slots meant for old Key Management
// keys that have been rotated. YubiKeys 4 and later support values between 0x82 and 0x95 (inclusive).
//
//	slot, ok := SlotRetiredKeyManagement(0x82)
//	if !ok {
//	    // unrecognized slot
//	}
//	pub, err := c.GenerateKey(managementKey, slot, key)
//
// https://developers.yubico.com/PIV/Introduction/Certificate_slots.html#_slot_82_95_retired_key_management
func SlotRetiredKeyManagement(key byte) (Slot, bool) {
	if key < 0x82 || key > 0x95 {
		return Slot{}, false
	}

	obj := doCertRetired1
	obj[2] += key - 0x82

	return Slot{
		Key:    key,
		Object: obj,
	}, true
}

// String returns the two-character hex representation of the slot
func (s Slot) String() string {
	return strconv.FormatUint(uint64(s.Key), 16)
}
