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

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/encoding/tlv"
)

// ECPPPrivateKey is a crypto.PrivateKey implementation for EC
// keys. It implements crypto.Signer and the method SharedKey performs
// Diffie-Hellman key agreements.
//
// Keys returned by Card.PrivateKey() may be type asserted to
// *ECPPPrivateKey, if the slot contains an EC key.
type ECPPPrivateKey struct {
	c    *Card
	slot Slot
	pub  *ecdsa.PublicKey
	auth KeyAuth
	pp   PINPolicy
}

// Public returns the public key associated with this private key.
func (k *ECPPPrivateKey) Public() crypto.PublicKey {
	return k.pub
}

var _ crypto.Signer = (*ECPPPrivateKey)(nil)

// Sign implements crypto.Signer.
func (k *ECPPPrivateKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return k.auth.do(k.c, k.pp, func(tx *iso.Transaction) ([]byte, error) {
		return signEC(tx, k.slot, k.pub, digest)
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
func (k *ECPPPrivateKey) SharedKey(peer *ecdsa.PublicKey) ([]byte, error) {
	if peer.Curve.Params().BitSize != k.pub.Curve.Params().BitSize {
		return nil, errMismatchingAlgorithms
	}
	msg := elliptic.Marshal(peer.Curve, peer.X, peer.Y)
	return k.auth.do(k.c, k.pp, func(tx *iso.Transaction) ([]byte, error) {
		var alg Algorithm
		size := k.pub.Params().BitSize
		switch size {
		case 256:
			alg = AlgECCP256
		case 384:
			alg = AlgECCP384
		default:
			return nil, UnsupportedCurveError{curve: size}
		}

		// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=118
		// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=93
		resp, err := sendTLV(k.c.tx, iso.InsGeneralAuthenticate, byte(alg), k.slot.Key,
			tlv.New(0x7c,
				tlv.New(0x82),
				tlv.New(0x85, msg),
			),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to execute command: %w", err)
		}

		rs, _, ok := resp.GetChild(0x7c, 0x82)
		if !ok {
			return nil, fmt.Errorf("%w: missing tag", errUnmarshal)
		}
		return rs, nil
	})
}

func decodeECPublic(tvs tlv.TagValues, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	p, _, ok := tvs.Get(0x86)
	if !ok {
		return nil, fmt.Errorf("%w: no points", errUnmarshal)
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

func signEC(tx *iso.Transaction, slot Slot, pub *ecdsa.PublicKey, data []byte) ([]byte, error) {
	alg, err := algEC(pub)
	if err != nil {
		return nil, err
	}

	// Same as the standard library
	// https://github.com/golang/go/blob/go1.13.5/src/crypto/ecdsa/ecdsa.go#L125-L128
	orderBytes := (pub.Params().BitSize + 7) / 8
	if len(data) > orderBytes {
		data = data[:orderBytes]
	}

	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=118
	resp, err := sendTLV(tx, iso.InsGeneralAuthenticate, byte(alg), slot.Key,
		tlv.New(0x7c,
			tlv.New(0x82),
			tlv.New(0x81, data)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}

	rs, _, ok := resp.GetChild(0x7c, 0x82)
	if !ok {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return rs, nil
}

func algEC(pub *ecdsa.PublicKey) (Algorithm, error) {
	size := pub.Params().BitSize
	switch size {
	case 256:
		return AlgECCP256, nil

	case 384:
		return AlgECCP384, nil

	default:
		return 0, UnsupportedCurveError{curve: size}
	}
}
