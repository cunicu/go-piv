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

	switch uint32(key) {
	case SlotAuthentication.Key:
		return SlotAuthentication, true
	case SlotSignature.Key:
		return SlotSignature, true
	case SlotCardAuthentication.Key:
		return SlotCardAuthentication, true
	case SlotKeyManagement.Key:
		return SlotKeyManagement, true
	}

	return RetiredKeyManagementSlot(uint32(key))
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
	SlotAuthentication     = Slot{0x9a, 0x5fc105}
	SlotSignature          = Slot{0x9c, 0x5fc10a}
	SlotCardAuthentication = Slot{0x9e, 0x5fc101}
	SlotKeyManagement      = Slot{0x9d, 0x5fc10b}

	slotAttestation = Slot{0xf9, 0x5fff01}
)

//nolint:gochecknoglobals
var retiredKeyManagementSlots = map[uint32]Slot{
	0x82: {0x82, 0x5fc10d},
	0x83: {0x83, 0x5fc10e},
	0x84: {0x84, 0x5fc10f},
	0x85: {0x85, 0x5fc110},
	0x86: {0x86, 0x5fc111},
	0x87: {0x87, 0x5fc112},
	0x88: {0x88, 0x5fc113},
	0x89: {0x89, 0x5fc114},
	0x8a: {0x8a, 0x5fc115},
	0x8b: {0x8b, 0x5fc116},
	0x8c: {0x8c, 0x5fc117},
	0x8d: {0x8d, 0x5fc118},
	0x8e: {0x8e, 0x5fc119},
	0x8f: {0x8f, 0x5fc11a},
	0x90: {0x90, 0x5fc11b},
	0x91: {0x91, 0x5fc11c},
	0x92: {0x92, 0x5fc11d},
	0x93: {0x93, 0x5fc11e},
	0x94: {0x94, 0x5fc11f},
	0x95: {0x95, 0x5fc120},
}

// RetiredKeyManagementSlot provides access to "retired" slots. Slots meant for old Key Management
// keys that have been rotated. YubiKeys 4 and later support values between 0x82 and 0x95 (inclusive).
//
//	slot, ok := RetiredKeyManagementSlot(0x82)
//	if !ok {
//	    // unrecognized slot
//	}
//	pub, err := yk.GenerateKey(managementKey, slot, key)
//
// https://developers.yubico.com/PIV/Introduction/Certificate_slots.html#_slot_82_95_retired_key_management
func RetiredKeyManagementSlot(key uint32) (Slot, bool) {
	slot, ok := retiredKeyManagementSlots[key]
	return slot, ok
}

// String returns the two-character hex representation of the slot
func (s Slot) String() string {
	return strconv.FormatUint(uint64(s.Key), 16)
}
