// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import "fmt"

// FormFactor enumerates the physical set of forms a key can take. USB-A vs.
// USB-C and Keychain vs. Nano (and FIPS variants for these).
type FormFactor int

// The mapping between known form factor values and their descriptions.
//
//nolint:gochecknoglobals
var formFactorStrings = map[FormFactor]string{
	FormFactorUSBAKeychain:          "USB-A Keychain",
	FormFactorUSBANano:              "USB-A Nano",
	FormFactorUSBCKeychain:          "USB-C Keychain",
	FormFactorUSBCNano:              "USB-C Nano",
	FormFactorUSBCLightningKeychain: "USB-C/Lightning Keychain",

	FormFactorUSBAKeychainFIPS:          "USB-A Keychain FIPS",
	FormFactorUSBANanoFIPS:              "USB-A Nano FIPS",
	FormFactorUSBCKeychainFIPS:          "USB-C Keychain FIPS",
	FormFactorUSBCNanoFIPS:              "USB-C Nano FIPS",
	FormFactorUSBCLightningKeychainFIPS: "USB-C/Lightning Keychain FIPS",
}

// String returns the human-readable description for the given form-factor
// value, or a fallback value for any other, unknown form-factor.
func (f FormFactor) String() string {
	if s, ok := formFactorStrings[f]; ok {
		return s
	}

	return fmt.Sprintf("unknown(0x%02x)", int(f))
}

// Formfactors recognized by this package. See the reference for more information:
// https://developers.yubico.com/yubikey-manager/Config_Reference.html#_form_factor
const (
	FormFactorUSBAKeychain          = 0x1
	FormFactorUSBANano              = 0x2
	FormFactorUSBCKeychain          = 0x3
	FormFactorUSBCNano              = 0x4
	FormFactorUSBCLightningKeychain = 0x5

	FormFactorUSBAKeychainFIPS          = 0x80 + FormFactorUSBAKeychain
	FormFactorUSBANanoFIPS              = 0x80 + FormFactorUSBANano
	FormFactorUSBCKeychainFIPS          = 0x80 + FormFactorUSBCKeychain
	FormFactorUSBCNanoFIPS              = 0x80 + FormFactorUSBCNano
	FormFactorUSBCLightningKeychainFIPS = 0x80 + FormFactorUSBCLightningKeychain
)
