// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import "fmt"

// Formfactor enumerates the physical set of forms a key can take. USB-A vs.
// USB-C and Keychain vs. Nano (and FIPS variants for these).
type Formfactor int

// The mapping between known Formfactor values and their descriptions.
//
//nolint:gochecknoglobals
var formFactorStrings = map[Formfactor]string{
	FormfactorUSBAKeychain:          "USB-A Keychain",
	FormfactorUSBANano:              "USB-A Nano",
	FormfactorUSBCKeychain:          "USB-C Keychain",
	FormfactorUSBCNano:              "USB-C Nano",
	FormfactorUSBCLightningKeychain: "USB-C/Lightning Keychain",

	FormfactorUSBAKeychainFIPS:          "USB-A Keychain FIPS",
	FormfactorUSBANanoFIPS:              "USB-A Nano FIPS",
	FormfactorUSBCKeychainFIPS:          "USB-C Keychain FIPS",
	FormfactorUSBCNanoFIPS:              "USB-C Nano FIPS",
	FormfactorUSBCLightningKeychainFIPS: "USB-C/Lightning Keychain FIPS",
}

// String returns the human-readable description for the given form-factor
// value, or a fallback value for any other, unknown form-factor.
func (f Formfactor) String() string {
	if s, ok := formFactorStrings[f]; ok {
		return s
	}
	return fmt.Sprintf("unknown(0x%02x)", int(f))
}

// Formfactors recognized by this package. See the reference for more information:
// https://developers.yubico.com/yubikey-manager/Config_Reference.html#_form_factor
const (
	FormfactorUSBAKeychain          = 0x1
	FormfactorUSBANano              = 0x2
	FormfactorUSBCKeychain          = 0x3
	FormfactorUSBCNano              = 0x4
	FormfactorUSBCLightningKeychain = 0x5

	FormfactorUSBAKeychainFIPS          = 0x81
	FormfactorUSBANanoFIPS              = 0x82
	FormfactorUSBCKeychainFIPS          = 0x83
	FormfactorUSBCNanoFIPS              = 0x84
	FormfactorUSBCLightningKeychainFIPS = 0x85
)
