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
	Algorithm        Algorithm
	PINPolicy        PINPolicy
	TouchPolicy      TouchPolicy
	Origin           Origin
	PublicKey        crypto.PublicKey
	RetriesTotal     int
	RetriesRemaining int
	IsDefault        bool
}

//nolint:gocognit
func (ki *Metadata) unmarshal(tvs tlv.TagValues) (err error) {
	// Algorithm
	if v, _, ok := tvs.Get(tagMetadataAlgo); ok {
		if l := len(v); l != 1 {
			return fmt.Errorf("%w for algorithm: %d", errUnexpectedLength, l)
		}

		ki.Algorithm = Algorithm(v[0])
	}

	// PIN & Touch Policy
	if v, _, ok := tvs.Get(tagMetadataPolicy); ok {
		if l := len(v); l != 2 {
			return fmt.Errorf("%w for PIN and touch policy: %d", errUnexpectedLength, l)
		}

		if ki.PINPolicy, ok = pinPolicyMapInv[v[0]]; !ok {
			if v[0] > 0 { // SlotCardManagement has no PIN policy
				return fmt.Errorf("%w: %x", errUnsupportedPinPolicy, v[0])
			}
		}

		if ki.TouchPolicy, ok = touchPolicyMapInv[v[1]]; !ok {
			return fmt.Errorf("%w: %x", errUnsupportedTouchPolicy, v[1])
		}
	}

	// Origin
	if v, _, ok := tvs.Get(tagMetadataOrigin); ok {
		if l := len(v); l != 1 {
			return fmt.Errorf("%w for origin: %d", errUnexpectedLength, l)
		}

		if ki.Origin, ok = originMapInv[v[0]]; !ok {
			return errUnsupportedOrigin
		}
	}

	// Public Key
	if v, _, ok := tvs.Get(tagMetadataPublicKey); ok {
		ki.PublicKey, err = decodePublic(v, ki.Algorithm)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %w", err)
		}
	}

	// Has default value
	if v, _, ok := tvs.Get(tagMetadataIsDefault); ok {
		if l := len(v); l != 1 {
			return fmt.Errorf("%w for default value: %d", errUnexpectedLength, l)
		}

		ki.IsDefault = v[0] != 0
	}

	// Number of retries left
	if v, _, ok := tvs.Get(tagMetadataRetries); ok {
		if l := len(v); l != 2 {
			return fmt.Errorf("%w for retries: %d", errUnexpectedLength, l)
		}

		ki.RetriesTotal = int(v[0])
		ki.RetriesRemaining = int(v[1])
	}

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
