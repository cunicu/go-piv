// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"crypto/ecdh"
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

	peerECDH, err := peer.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert key: %w", err)
	}

	return k.auth.do(k.c, k.pp, func(_ *iso.Transaction) ([]byte, error) {
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
				tlv.New(0x85, peerECDH.Bytes()),
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

func decodeECDSAPublic(tvs tlv.TagValues, curve ecdh.Curve) (*ecdsa.PublicKey, error) {
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	p, _, ok := tvs.Get(0x86)
	if !ok {
		return nil, fmt.Errorf("%w: no points", errUnmarshal)
	}

	pk, err := curve.NewPublicKey(p)
	if err != nil {
		return nil, err
	}

	return ecdhToECDSAPublicKey(pk)
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

func ecdhToECDSAPublicKey(key *ecdh.PublicKey) (*ecdsa.PublicKey, error) {
	rawKey := key.Bytes()
	switch key.Curve() {
	case ecdh.P256():
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(0).SetBytes(rawKey[1:33]),
			Y:     big.NewInt(0).SetBytes(rawKey[33:]),
		}, nil
	case ecdh.P384():
		return &ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     big.NewInt(0).SetBytes(rawKey[1:49]),
			Y:     big.NewInt(0).SetBytes(rawKey[49:]),
		}, nil
	case ecdh.P521():
		return &ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     big.NewInt(0).SetBytes(rawKey[1:67]),
			Y:     big.NewInt(0).SetBytes(rawKey[67:]),
		}, nil
	default:
		return nil, UnsupportedCurveError{}
	}
}
