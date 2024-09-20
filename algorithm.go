// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package piv

import "fmt"

// Algorithm represents a specific algorithm and bit size supported by the PIV
// specification.
type Algorithm byte

// Algorithms supported by this package. Note that not all cards will support
// every algorithm.
//
// For algorithm discovery, see: https://github.com/go-piv/piv-go/issues/1
const (
	// NIST SP 800-78-4
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=21
	AlgRSA2048 Algorithm = 0x07 // RSA 2048 bit modulus, 65537 ≤ exponent ≤ 2256 - 1
	AlgECCP256 Algorithm = 0x11 // ECC: Curve P-256
	AlgECCP384 Algorithm = 0x14 // ECC: Curve P-384

	// NIST SP 800-78-5 ipd (Initial Public Draft)
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-78-5.ipd.pdf#page=12
	Alg3DESSalt Algorithm = 0x00 // 3 Key Triple DES – ECB (deprecated)
	Alg3DES     Algorithm = 0x03 // 3 Key Triple DES – ECB (deprecated)
	AlgRSA3072  Algorithm = 0x05 // RSA 3072 bit modulus, 65537 ≤ exponent ≤ 2256 - 1
	AlgRSA1024  Algorithm = 0x06 // RSA 1024 bit modulus, 65537 ≤ exponent ≤ 2256 - 1
	AlgAES128   Algorithm = 0x08 // AES-128 – ECB
	AlgAES192   Algorithm = 0x0A // AES-192 – ECB
	AlgAES256   Algorithm = 0x0C // AES-256 – ECB
	AlgCS2      Algorithm = 0x27 // Cipher Suite 2
	AlgCS7      Algorithm = 0x2E // Cipher Suite 7

	// Non-standard extensions
	AlgPIN Algorithm = 0xFF

	// YubiKey 5.7 Firmware Specifics - PIV Enhancements - Additional Key Types Supported
	//
	// https://docs.yubico.com/hardware/yubikey/yk-tech-manual/5.7-firmware-specifics.html#additional-key-types-supported
	AlgRSA4096 Algorithm = 0x16

	AlgEd25519 Algorithm = 0xE0 // YubiKey
	AlgX25519  Algorithm = 0xE1 // YubiKey

	// Trussed PIV authenticator (NitroKey / SoloKeys)
	//
	// https://github.com/Nitrokey/piv-authenticator/blob/efb4632b3f498af6732fc716354af746f3960038/tests/command_response.rs#L58-L72

	// AlgECCP521 Algorithm = 0x15
	// AlgRSA3072 Algorithm = 0xE0
	// AlgRSA4096 Algorithm = 0xE1
	// AlgEd25519 Algorithm = 0xE2
	// AlgX25519  Algorithm = 0xE3
	// AlgEd448   Algorithm = 0xE4
	// AlgX448    Algorithm = 0xE5

	// Internal algorithms for testing
	algRSA512  Algorithm = 0xF0
	algECCP224 Algorithm = 0xF1
	algECCP521 Algorithm = 0xF2
)

func (a Algorithm) String() string {
	switch a {
	case AlgRSA1024, AlgRSA2048, AlgRSA3072, AlgRSA4096, algRSA512:
		return fmt.Sprintf("RSA-%d", a.bits())

	case AlgECCP256, AlgECCP384, algECCP224, algECCP521:
		return fmt.Sprintf("P-%d", a.bits())

	case Alg3DESSalt:
		return "3DESSalt"
	case Alg3DES:
		return "3DES"

	case AlgAES128, AlgAES192, AlgAES256:
		return fmt.Sprintf("AES-%d", a.bits())

	case AlgCS2:
		return "CS2"
	case AlgCS7:
		return "CS7"

	case AlgPIN:
		return "PIN"

	case AlgEd25519:
		return "Ed25519"
	case AlgX25519:
		return "X25519"

	default:
		return ""
	}
}

func (a Algorithm) bits() int {
	switch a {
	case algRSA512:
		return 512
	case AlgRSA1024:
		return 1024
	case AlgRSA2048:
		return 2048
	case AlgRSA3072:
		return 3072
	case AlgRSA4096:
		return 4096

	case algECCP224:
		return 224
	case AlgECCP256:
		return 256
	case AlgECCP384:
		return 384
	case algECCP521:
		return 521

	case AlgAES128:
		return 128
	case AlgAES192:
		return 192
	case AlgAES256:
		return 256

	default:
		return 0
	}
}
