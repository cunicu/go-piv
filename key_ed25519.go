// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"io"
)

type keyEd25519 struct {
	yk   *YubiKey
	slot Slot
	pub  ed25519.PublicKey
	auth KeyAuth
	pp   PINPolicy
}

func (k *keyEd25519) Public() crypto.PublicKey {
	return k.pub
}

func (k *keyEd25519) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return k.auth.do(k.yk, k.pp, func(tx *scTx) ([]byte, error) {
		return skSignEd25519(tx, k.slot, k.pub, digest)
	})
}

// This function only works on SoloKeys prototypes and other PIV devices that choose
// to implement Ed25519 signatures under alg 0x22.
func skSignEd25519(tx *scTx, slot Slot, _ ed25519.PublicKey, digest []byte) ([]byte, error) {
	// Adaptation of
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=118
	cmd := apdu{
		instruction: insAuthenticate,
		param1:      algEd25519,
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

func decodeEd25519Public(b []byte) (ed25519.PublicKey, error) {
	// Adaptation of
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	p, _, err := unmarshalASN1(b, 2, 0x06)
	if err != nil {
		return nil, fmt.Errorf("%w points: %w", errUnmarshal, err)
	}
	if len(p) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w of points: %d", errUnexpectedLength, len(p))
	}
	return ed25519.PublicKey(p), nil
}
