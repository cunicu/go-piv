// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"fmt"

	"cunicu.li/go-iso7816/encoding/tlv"
)

// Metadata holds unprotected metadata about a key slot.
type Metadata struct {
	Algorithm   Algorithm
	PINPolicy   PINPolicy
	TouchPolicy TouchPolicy
	Origin      Origin
	PublicKey   crypto.PublicKey
}

//nolint:gocognit
func (ki *Metadata) unmarshal(tvs tlv.TagValues) (err error) {
	// Algorithm
	if v, _, ok := tvs.Get(0x01); ok {
		if len(v) != 1 {
			return fmt.Errorf("%w for algorithm", errUnexpectedLength)
		}

		ki.Algorithm = Algorithm(v[0])
	}

	// PIN & Touch Policy
	if v, _, ok := tvs.Get(0x02); ok {
		if len(v) != 2 {
			return fmt.Errorf("%w for pin and touch policy", errUnexpectedLength)
		}

		if ki.PINPolicy, ok = pinPolicyMapInv[v[0]]; !ok {
			return errUnsupportedPinPolicy
		}

		if ki.TouchPolicy, ok = touchPolicyMapInv[v[1]]; !ok {
			return errUnsupportedTouchPolicy
		}
	}

	// Origin
	if v, _, ok := tvs.Get(0x03); ok {
		if len(v) != 1 {
			return fmt.Errorf("%w for origin", errUnexpectedLength)
		}

		if ki.Origin, ok = originMapInv[v[0]]; !ok {
			return errUnsupportedOrigin
		}
	}

	// Public Key
	if v, _, ok := tvs.Get(0x04); ok {
		ki.PublicKey, err = decodePublic(v, ki.Algorithm)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %w", err)
		}
	}

	// TODO: According to the Yubico website, we get two more fields,
	// if we pass 0x80 or 0x81 as slots:
	//     1. Default value (for PIN/PUK and management key): Whether the
	//        default value is used.
	//     2. Retries (for PIN/PUK): The number of retries remaining
	// However, it seems the reference implementation does not expect
	// these and can not parse them out:
	// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-2.3.1/lib/util.c#L1529
	// For now, we just ignore them.

	// Default Value
	// if _, v, ok := tvs.Get(0x05); ok {
	// }

	// Retries
	// if _, v, ok := tvs.Get(0x06); ok {
	// }

	return nil
}

// Metadata returns public information about the given key slot. It is only
// supported by YubiKeys with a version >= 5.3.0.
//
// https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html#_get_metadata
func (c *Card) Metadata(slot Slot) (*Metadata, error) {
	resp, err := sendTLV(c.tx, insGetMetadata, 0x00, slot.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}

	ki := &Metadata{}
	if err := ki.unmarshal(resp); err != nil {
		return nil, err
	}

	return ki, nil
}
