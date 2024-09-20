// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"io"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/encoding/tlv"
)

type keyEd25519 struct {
	c    *Card
	slot Slot
	pub  ed25519.PublicKey
	auth KeyAuth
	pp   PINPolicy
}

func (k *keyEd25519) Public() crypto.PublicKey {
	return k.pub
}

// This function only works on YubiKeys with firmware version 5.7.0 and higher as well
// as SoloKeys prototypes and other PIV devices that choose to implement Ed25519
// signatures under algorithm type 0xE0 / 0x22.
func (k *keyEd25519) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return k.auth.do(k.c, k.pp, func(tx *iso.Transaction) ([]byte, error) {
		return signEd25519(tx, k.slot, digest)
	})
}

// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
func decodeEd25519Public(tvs tlv.TagValues) (ed25519.PublicKey, error) {
	p, _, ok := tvs.Get(0x86)
	if !ok {
		return nil, fmt.Errorf("%w points", errUnmarshal)
	}

	if len(p) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w of points: %d", errUnexpectedLength, len(p))
	}

	return ed25519.PublicKey(p), nil
}

// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=118
func signEd25519(tx *iso.Transaction, slot Slot, data []byte) ([]byte, error) {
	resp, err := sendTLV(tx, iso.InsGeneralAuthenticate, byte(AlgEd25519), slot.Key,
		tlv.New(0x7c,
			tlv.New(0x82),
			tlv.New(0x81, data),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}

	rs, _, ok := resp.GetChild(0x7c, 0x82)
	if !ok {
		return nil, fmt.Errorf("%w response signature: missing tag", errUnmarshal)
	}

	return rs, nil
}
