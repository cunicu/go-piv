// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"io"
	"math/big"
)

// ECDSAPrivateKey is a crypto.PrivateKey implementation for ECDSA
// keys. It implements crypto.Signer and the method SharedKey performs
// Diffie-Hellman key agreements.
//
// Keys returned by Card.PrivateKey() may be type asserted to
// *ECDSAPrivateKey, if the slot contains an ECDSA key.
type ECDSAPrivateKey struct {
	c    *Card
	slot Slot
	pub  *ecdsa.PublicKey
	auth KeyAuth
	pp   PINPolicy
}

// Public returns the public key associated with this private key.
func (k *ECDSAPrivateKey) Public() crypto.PublicKey {
	return k.pub
}

var _ crypto.Signer = (*ECDSAPrivateKey)(nil)

// Sign implements crypto.Signer.
func (k *ECDSAPrivateKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return k.auth.do(k.c, k.pp, func(tx *scTx) ([]byte, error) {
		return signECDSA(tx, k.slot, k.pub, digest)
	})
}

// SharedKey performs a Diffie-Hellman key agreement with the peer
// to produce a shared secret key.
//
// Peer's public key must use the same algorithm as the key in
// this slot, or an error will be returned.
//
// Length of the result depends on the types and sizes of the keys
// used for the operation. Callers should use a cryptographic key
// derivation function to extract the amount of bytes they need.
func (k *ECDSAPrivateKey) SharedKey(peer *ecdsa.PublicKey) ([]byte, error) {
	if peer.Curve.Params().BitSize != k.pub.Curve.Params().BitSize {
		return nil, errMismatchingAlgorithms
	}
	msg := elliptic.Marshal(peer.Curve, peer.X, peer.Y)
	return k.auth.do(k.c, k.pp, func(tx *scTx) ([]byte, error) {
		var alg byte
		size := k.pub.Params().BitSize
		switch size {
		case 256:
			alg = algECS256
		case 384:
			alg = algECCP384
		default:
			return nil, unsupportedCurveError{curve: size}
		}

		// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=118
		// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=93
		cmd := apdu{
			instruction: insAuthenticate,
			param1:      alg,
			param2:      byte(k.slot.Key),
			data: marshalASN1(0x7c,
				append([]byte{0x82, 0x00},
					marshalASN1(0x85, msg)...)),
		}
		resp, err := tx.Transmit(cmd)
		if err != nil {
			return nil, fmt.Errorf("failed to execute command: %w", err)
		}
		sig, _, err := unmarshalASN1(resp, 1, 0x1c) // 0x7c
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal response: %w", err)
		}
		rs, _, err := unmarshalASN1(sig, 2, 0x02) // 0x82
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal response signature: %w", err)
		}
		return rs, nil
	})
}

func signECDSA(tx *scTx, slot Slot, pub *ecdsa.PublicKey, digest []byte) ([]byte, error) {
	var alg byte
	size := pub.Params().BitSize
	switch size {
	case 256:
		alg = algECS256
	case 384:
		alg = algECCP384
	default:
		return nil, unsupportedCurveError{curve: size}
	}

	// Same as the standard library
	// https://github.com/golang/go/blob/go1.13.5/src/crypto/ecdsa/ecdsa.go#L125-L128
	orderBytes := (size + 7) / 8
	if len(digest) > orderBytes {
		digest = digest[:orderBytes]
	}

	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=118
	cmd := apdu{
		instruction: insAuthenticate,
		param1:      alg,
		param2:      byte(slot.Key),
		data: marshalASN1(0x7c,
			append([]byte{0x82, 0x00},
				marshalASN1(0x81, digest)...)),
	}
	resp, err := tx.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}
	sig, _, err := unmarshalASN1(resp, 1, 0x1c) // 0x7c
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	rs, _, err := unmarshalASN1(sig, 2, 0x02) // 0x82
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response signature: %w", err)
	}
	return rs, nil
}

func decodeECPublic(b []byte, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	p, _, err := unmarshalASN1(b, 2, 0x06)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal points: %w", err)
	}
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=96
	size := curve.Params().BitSize / 8
	if len(p) != (size*2)+1 {
		return nil, fmt.Errorf("%w of points: %d", errUnexpectedLength, len(p))
	}
	// Are points uncompressed?
	if p[0] != 0x04 {
		return nil, errPointsNotCompressed
	}
	p = p[1:]
	var x, y big.Int
	x.SetBytes(p[:size])
	y.SetBytes(p[size:])
	if !curve.IsOnCurve(&x, &y) {
		return nil, errPointsNotOnCurve
	}
	return &ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}, nil
}
