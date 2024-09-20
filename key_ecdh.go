// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto/ecdh"
	"fmt"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/encoding/tlv"
)

type keyX25519 struct {
	c    *Card
	slot Slot
	pub  *ecdh.PublicKey
	auth KeyAuth
	pp   PINPolicy
}

func (k *keyX25519) Public() *ecdh.PublicKey {
	return k.pub
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
func (k *keyX25519) SharedKey(peer *ecdh.PublicKey) ([]byte, error) {
	if peer.Curve() != k.pub.Curve() {
		return nil, errMismatchingAlgorithms
	}

	return k.auth.do(k.c, k.pp, func(tx *iso.Transaction) ([]byte, error) {
		// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=118
		// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=93
		resp, err := sendTLV(k.c.tx, iso.InsGeneralAuthenticate, byte(AlgX25519), k.slot.Key,
			tlv.New(0x7c,
				tlv.New(0x82),
				tlv.New(0x85, peer.Bytes()),
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

// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
func decodeX25519Public(tvs tlv.TagValues) (*ecdh.PublicKey, error) {
	p, _, ok := tvs.Get(0x86)
	if !ok {
		return nil, fmt.Errorf("%w points", errUnmarshal)
	}

	if len(p) != 32 {
		return nil, fmt.Errorf("%w of points: %d", errUnexpectedLength, len(p))
	}

	return ecdh.X25519().NewPublicKey(p)
}
