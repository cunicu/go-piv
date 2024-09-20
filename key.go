// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"

	"cunicu.li/go-iso7816/encoding/tlv"
)

var (
	// errMismatchingAlgorithms is returned when a cryptographic operation
	// is given keys using different algorithms.
	errMismatchingAlgorithms = errors.New("mismatching key algorithms")

	// errUnsupportedKeySize is returned when a key has an unsupported size
	errUnsupportedKeySize = errors.New("unsupported key size")

	errInvalidPKCS1Padding      = errors.New("invalid PKCS#1 v1.5 padding")
	errInvalidSerialNumber      = errors.New("invalid serial number")
	errMissingPIN               = errors.New("PIN required but wasn't provided")
	errParseCert                = errors.New("failed to parse certificate")
	errUnexpectedLength         = errors.New("unexpected length")
	errUnmarshal                = errors.New("failed to unmarshal")
	errUnsupportedAlgorithm     = errors.New("unsupported algorithm")
	errUnsupportedHashAlgorithm = errors.New("unsupported hash algorithm")
	errUnsupportedPinPolicy     = errors.New("unsupported PIN policy")
	errUnsupportedTouchPolicy   = errors.New("unsupported touch policy")
	errUnsupportedKeyType       = errors.New("unsupported key type")
	errUnsupportedOrigin        = errors.New("unsupported origin")
)

// UnsupportedCurveError is used when a key has an unsupported curve
type UnsupportedCurveError struct {
	curve int
}

func (e UnsupportedCurveError) Error() string {
	return fmt.Sprintf("unsupported curve: %d", e.curve)
}

//nolint:gochecknoglobals
var (
	extIDFirmwareVersion = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 3})
	extIDSerialNumber    = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 7})
	extIDKeyPolicy       = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 8})
	extIDFormFactor      = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 9})
)

// Key is used for key generation and holds different options for the key.
//
// While keys can have default PIN and touch policies, this package currently
// doesn't support this option, and all fields must be provided.
type Key struct {
	// Algorithm to use when generating the key.
	Algorithm Algorithm

	// PINPolicy for the key.
	//
	// BUG(ericchiang): some older YubiKeys (third generation) will silently
	// drop this value. If PINPolicyNever or PINPolicyOnce is supplied but the
	// key still requires a PIN every time, you may be using a buggy key and
	// should supply PINPolicyAlways.
	//
	// https://github.com/go-piv/piv-go/issues/60
	PINPolicy PINPolicy

	// TouchPolicy for the key.
	TouchPolicy TouchPolicy
}

// GenerateKey generates an asymmetric key on the card, returning the key's
// public key.
func (c *Card) GenerateKey(key ManagementKey, slot Slot, opts Key) (crypto.PublicKey, error) {
	if err := c.authenticate(key); err != nil {
		return nil, fmt.Errorf("failed to authenticate with management key: %w", err)
	}

	tp, ok := touchPolicyMap[opts.TouchPolicy]
	if !ok {
		return nil, errUnsupportedTouchPolicy
	}

	pp, ok := pinPolicyMap[opts.PINPolicy]
	if !ok {
		return nil, errUnsupportedPinPolicy
	}

	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	resp, err := sendTLV(c.tx, insGenerateAsymmetric, 0, slot.Key,
		tlv.New(0xac,
			tlv.New(tagAlg, byte(opts.Algorithm)),
			tlv.New(tagPINPolicy, pp),
			tlv.New(tagTouchPolicy, tp),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}

	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	pub, _, ok := resp.Get(0x7f49)
	if !ok {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return decodePublic(pub, opts.Algorithm)
}

func decodePublic(b []byte, alg Algorithm) (pub crypto.PublicKey, err error) {
	tvs, err := tlv.DecodeBER(b)
	if err != nil {
		return nil, err
	}

	switch alg {
	case AlgRSA1024, AlgRSA2048, AlgRSA3072, AlgRSA4096:
		if pub, err = decodeRSAPublic(tvs); err != nil {
			return nil, fmt.Errorf("failed to decode RSA public key: %w", err)
		}

	case AlgECCP256:
		if pub, err = decodeECDSAPublic(tvs, ecdh.P256()); err != nil {
			return nil, fmt.Errorf("failed to decode P256 public key: %w", err)
		}

	case AlgECCP384:
		if pub, err = decodeECDSAPublic(tvs, ecdh.P384()); err != nil {
			return nil, fmt.Errorf("failed to decode P384 public key: %w", err)
		}

	case AlgEd25519:
		if pub, err = decodeEd25519Public(tvs); err != nil {
			return nil, fmt.Errorf("failed to decode Ed25519 public key: %w", err)
		}

	case AlgX25519:
		if pub, err = decodeX25519Public(tvs); err != nil {
			return nil, fmt.Errorf("failed to decode X25519 public key: %w", err)
		}

	default:
		return nil, errUnsupportedAlgorithm
	}

	return pub, nil
}

// PrivateKey is used to access signing and decryption options for the key
// stored in the slot. The returned key implements crypto.Signer and/or
// crypto.Decrypter depending on the key type.
//
// If the public key hasn't been stored externally, it can be provided by
// fetching the slot's attestation certificate:
//
//	cert, err := c.Attest(slot)
//	if err != nil {
//		// ...
//	}
//	priv, err := c.PrivateKey(slot, cert.PublicKey, auth)
func (c *Card) PrivateKey(slot Slot, public crypto.PublicKey, auth KeyAuth) (crypto.PrivateKey, error) {
	pp := PINPolicyNever
	if _, ok := pinPolicyMap[auth.PINPolicy]; ok {
		// If the PIN policy is manually specified, trust that value instead of
		// trying to use the attestation certificate.
		pp = auth.PINPolicy
	} else if auth.PIN != "" || auth.PINPrompt != nil {
		// Attempt to determine the key's PIN policy. This helps inform the
		// strategy for when to prompt for a PIN.
		policy, err := pinPolicy(c, slot)
		if err != nil {
			return nil, err
		}
		pp = policy
	}

	switch pub := public.(type) {
	case *ecdsa.PublicKey:
		return &ECPPPrivateKey{c, slot, pub, auth, pp}, nil

	case ed25519.PublicKey:
		return &keyEd25519{c, slot, pub, auth, pp}, nil

	case *ecdh.PublicKey:
		return &keyX25519{c, slot, pub, auth, pp}, nil

	case *rsa.PublicKey:
		return &keyRSA{c, slot, pub, auth, pp}, nil

	default:
		return nil, fmt.Errorf("%w: %T", errUnsupportedKeyType, public)
	}
}

// SetPrivateKeyInsecure is an insecure method which imports a private key into the slot.
// Users should almost always use GeneratePrivateKey() instead.
//
// Importing a private key breaks functionality provided by this package, including
// AttestationCertificate() and Attest(). There are no stability guarantees for other
// methods for imported private keys.
//
// Keys generated outside of the YubiKey should not be considered hardware-backed,
// as there's no way to prove the key wasn't copied, exfiltrated, or replaced with malicious
// material before being imported.
func (c *Card) SetPrivateKeyInsecure(key ManagementKey, slot Slot, private crypto.PrivateKey, policy Key) error {
	// Reference implementation
	// https://github.com/Yubico/yubico-piv-tool/blob/671a5740ef09d6c5d9d33f6e5575450750b58bde/lib/ykpiv.c#L1812

	if err := c.authenticate(key); err != nil {
		return fmt.Errorf("failed to authenticate with management key: %w", err)
	}

	tp, ok := touchPolicyMap[policy.TouchPolicy]
	if !ok {
		return errUnsupportedTouchPolicy
	}

	pp, ok := pinPolicyMap[policy.PINPolicy]
	if !ok {
		return errUnsupportedPinPolicy
	}

	tvs := tlv.TagValues{
		tlv.New(tagPINPolicy, pp),
		tlv.New(tagTouchPolicy, tp),
	}

	pad := func(l int, b []byte) (k []byte) {
		k = make([]byte, l)
		p := len(k) - len(b)
		copy(k[p:], b)
		return k
	}

	var elemLen int
	switch priv := private.(type) {
	case *rsa.PrivateKey:
		switch priv.N.BitLen() {
		case 1024:
			policy.Algorithm = AlgRSA1024
			elemLen = 64

		case 2048:
			policy.Algorithm = AlgRSA2048
			elemLen = 128

		case 3072:
			policy.Algorithm = AlgRSA3072
			elemLen = 192

		case 4096:
			policy.Algorithm = AlgRSA4096
			elemLen = 256

		default:
			return errUnsupportedKeySize
		}

		priv.Precompute()

		tvs = append(tvs,
			tlv.New(0x01, pad(elemLen, priv.Primes[0].Bytes())),        // P
			tlv.New(0x02, pad(elemLen, priv.Primes[1].Bytes())),        // Q
			tlv.New(0x03, pad(elemLen, priv.Precomputed.Dp.Bytes())),   // dP
			tlv.New(0x04, pad(elemLen, priv.Precomputed.Dq.Bytes())),   // dQ
			tlv.New(0x05, pad(elemLen, priv.Precomputed.Qinv.Bytes())), // Qinv
		)

	case *ecdsa.PrivateKey:
		size := priv.PublicKey.Params().BitSize
		switch size {
		case 256:
			policy.Algorithm = AlgECCP256
			elemLen = 32

		case 384:
			policy.Algorithm = AlgECCP384
			elemLen = 48

		default:
			return UnsupportedCurveError{curve: size}
		}

		tvs = append(tvs, tlv.New(0x06, pad(elemLen, priv.D.Bytes()))) // S value

	case *ed25519.PrivateKey:
		tvs = append(tvs, tlv.New(0x07, priv.Seed()))

	case *ecdh.PrivateKey:
		if priv.Curve() != ecdh.X25519() {
			return UnsupportedCurveError{}
		}

		tvs = append(tvs, tlv.New(0x08, priv.Bytes()))

	default:
		return errUnsupportedKeyType
	}

	// This command is a Yubico PIV extension.
	//
	// https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
	if _, err := sendTLV(c.tx, insImportKey, byte(policy.Algorithm), slot.Key, tvs...); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	return nil
}

// MoveKey moves a key from any slot except F9 (SlotAttestation) to any other slot except F9 (SlotAttestation).
//
// This enables retaining retired encryption keys on the device to decrypt older messages.
//
// Note: This is a YubiKey specific extension to PIV. Its supported by YubiKeys with firmware 5.7.0 or newer.
func (c *Card) MoveKey(key ManagementKey, from, to Slot) error {
	if err := c.authenticate(key); err != nil {
		return fmt.Errorf("failed to authenticate with management key: %w", err)
	}

	_, err := send(c.tx, insMoveDeleteKey, to.Key, from.Key, nil)

	return err
}

// DeleteKey deletes a key  from any slot, including F9 (SlotAttestation).
//
// This enables destroying key material without overwriting with bogus data or resetting the PIV application.
//
// Note: This is a YubiKey specific extension to PIV. Its supported by YubiKeys with firmware 5.7.0 or newer.
func (c *Card) DeleteKey(key ManagementKey, slot Slot) error {
	return c.MoveKey(key, slot, SlotGraveyard)
}
