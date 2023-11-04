// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	// errMismatchingAlgorithms is returned when a cryptographic operation
	// is given keys using different algorithms.
	errMismatchingAlgorithms = errors.New("mismatching key algorithms")

	// errUnsupportedKeySize is returned when a key has an unsupported size
	errUnsupportedKeySize = errors.New("unsupported key size")

	errInvalidPKCS1Padding      = errors.New("invalid PKCS#1 v1.5 padding")
	errInvalidSerialNumber      = errors.New("invalid serial number")
	errMissingPIN               = errors.New("pin required but wasn't provided")
	errParseCert                = errors.New("failed to parse certificate")
	errUnexpectedLength         = errors.New("unexpected length")
	errUnmarshal                = errors.New("failed to unmarshal")
	errUnsupportedAlgorithm     = errors.New("unsupported algorithm")
	errUnsupportedHashAlgorithm = errors.New("unsupported hash algorithm")
	errUnsupportedPinPolicy     = errors.New("unsupported pin policy")
	errUnsupportedTouchPolicy   = errors.New("unsupported touch policy")
	errUnsupportedKeyType       = errors.New("unsupported key type")
	errUnsupportedOrigin        = errors.New("unsupported origin")
	errPointsNotOnCurve         = errors.New("resulting points are not on curve")
	errPointsNotCompressed      = errors.New("points were not uncompressed")
	errUnexpectedClassTag       = errors.New("unexpected class/tag")
)

// unsupportedCurveError is used when a key has an unsupported curve
type unsupportedCurveError struct {
	curve int
}

func (e unsupportedCurveError) Error() string {
	return fmt.Sprintf("unsupported curve: %d", e.curve)
}

// Slot is a private key and certificate combination managed by the security key.
type Slot struct {
	// Key is a reference for a key type.
	//
	// See: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=32
	Key uint32
	// Object is a reference for data object.
	//
	// See: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=30
	Object uint32
}

//nolint:gochecknoglobals
var (
	extIDFirmwareVersion = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 3})
	extIDSerialNumber    = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 7})
	extIDKeyPolicy       = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 8})
	extIDFormFactor      = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 9})
)

// Version encodes a major, minor, and patch version.
type Version struct {
	Major int
	Minor int
	Patch int
}

const (
	tagPINPolicy   = 0xaa
	tagTouchPolicy = 0xab
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
	// should supply PINPolicyAlways. See https://cunicu.li/go-piv/issues/60
	PINPolicy PINPolicy
	// TouchPolicy for the key.
	TouchPolicy TouchPolicy
}

// GenerateKey generates an asymmetric key on the card, returning the key's
// public key.
func (c *Card) GenerateKey(key [24]byte, slot Slot, opts Key) (crypto.PublicKey, error) {
	if err := authenticate(c.tx, key, c.rand); err != nil {
		return nil, fmt.Errorf("failed to authenticate with management key: %w", err)
	}

	alg, ok := algorithmsMap[opts.Algorithm]
	if !ok {
		return nil, errUnsupportedAlgorithm
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
	cmd := apdu{
		instruction: insGenerateAsymmetric,
		param2:      byte(slot.Key),
		data: []byte{
			0xac,
			0x09, // length of remaining data
			algTag, 0x01, alg,
			tagPINPolicy, 0x01, pp,
			tagTouchPolicy, 0x01, tp,
		},
	}
	resp, err := c.tx.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}

	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	obj, _, err := unmarshalASN1(resp, 1, 0x49)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return decodePublic(obj, opts.Algorithm)
}

func decodePublic(b []byte, alg Algorithm) (crypto.PublicKey, error) {
	var curve elliptic.Curve
	switch alg {
	case AlgorithmRSA1024, AlgorithmRSA2048:
		pub, err := decodeRSAPublic(b)
		if err != nil {
			return nil, fmt.Errorf("failed to decode RSA public key: %w", err)
		}
		return pub, nil
	case AlgorithmEC256:
		curve = elliptic.P256()
	case AlgorithmEC384:
		curve = elliptic.P384()
	case AlgorithmEd25519:
		pub, err := decodeEd25519Public(b)
		if err != nil {
			return nil, fmt.Errorf("failed to decode ed25519 public key: %w", err)
		}
		return pub, nil
	default:
		return nil, errUnsupportedAlgorithm
	}
	pub, err := decodeECPublic(b, curve)
	if err != nil {
		return nil, fmt.Errorf("failed to decode elliptic curve public key: %w", err)
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
		return &ECDSAPrivateKey{c, slot, pub, auth, pp}, nil
	case ed25519.PublicKey:
		return &keyEd25519{c, slot, pub, auth, pp}, nil
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
func (c *Card) SetPrivateKeyInsecure(key [24]byte, slot Slot, private crypto.PrivateKey, policy Key) error {
	// Reference implementation
	// https://github.com/Yubico/yubico-piv-tool/blob/671a5740ef09d6c5d9d33f6e5575450750b58bde/lib/ykpiv.c#L1812

	params := make([][]byte, 0)

	var paramTag byte
	var elemLen int

	switch priv := private.(type) {
	case *rsa.PrivateKey:
		paramTag = 0x01
		switch priv.N.BitLen() {
		case 1024:
			policy.Algorithm = AlgorithmRSA1024
			elemLen = 64
		case 2048:
			policy.Algorithm = AlgorithmRSA2048
			elemLen = 128
		default:
			return errUnsupportedKeySize
		}

		priv.Precompute()

		params = append(params, priv.Primes[0].Bytes())        // P
		params = append(params, priv.Primes[1].Bytes())        // Q
		params = append(params, priv.Precomputed.Dp.Bytes())   // dP
		params = append(params, priv.Precomputed.Dq.Bytes())   // dQ
		params = append(params, priv.Precomputed.Qinv.Bytes()) // Qinv
	case *ecdsa.PrivateKey:
		paramTag = 0x6
		size := priv.PublicKey.Params().BitSize
		switch size {
		case 256:
			policy.Algorithm = AlgorithmEC256
			elemLen = 32
		case 384:
			policy.Algorithm = AlgorithmEC384
			elemLen = 48
		default:
			return unsupportedCurveError{curve: size}
		}

		// S value
		privateKey := make([]byte, elemLen)
		valueBytes := priv.D.Bytes()
		padding := len(privateKey) - len(valueBytes)
		copy(privateKey[padding:], valueBytes)

		params = append(params, privateKey)
	default:
		return errUnsupportedKeyType
	}

	elemLenASN1 := marshalASN1Length(uint64(elemLen))

	tags := make([]byte, 0)
	for i, param := range params {
		tag := paramTag + byte(i)
		tags = append(tags, tag)
		tags = append(tags, elemLenASN1...)

		padding := elemLen - len(param)
		param = append(make([]byte, padding), param...)
		tags = append(tags, param...)
	}

	if err := authenticate(c.tx, key, c.rand); err != nil {
		return fmt.Errorf("failed to authenticate with management key: %w", err)
	}

	return importKey(c.tx, tags, slot, policy)
}

func importKey(tx *scTx, tags []byte, slot Slot, o Key) error {
	alg, ok := algorithmsMap[o.Algorithm]
	if !ok {
		return errUnsupportedAlgorithm
	}
	tp, ok := touchPolicyMap[o.TouchPolicy]
	if !ok {
		return errUnsupportedTouchPolicy
	}
	pp, ok := pinPolicyMap[o.PINPolicy]
	if !ok {
		return errUnsupportedPinPolicy
	}

	// This command is a Yubico PIV extension.
	// https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
	cmd := apdu{
		instruction: insImportKey,
		param1:      alg,
		param2:      byte(slot.Key),
		data: append(tags, []byte{
			tagPINPolicy, 0x01, pp,
			tagTouchPolicy, 0x01, tp,
		}...),
	}

	if _, err := tx.Transmit(cmd); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	return nil
}

// PKCS#1 v15 is largely informed by the standard library
// https://github.com/golang/go/blob/go1.13.5/src/crypto/rsa/pkcs1v15.go

//nolint:gochecknoglobals
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}
