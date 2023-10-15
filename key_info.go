// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"encoding/asn1"
	"fmt"
)

// KeyInfo holds unprotected metadata about a key slot.
type KeyInfo struct {
	Algorithm   Algorithm
	PINPolicy   PINPolicy
	TouchPolicy TouchPolicy
	Origin      Origin
	PublicKey   crypto.PublicKey
}

//nolint:gocognit
func (ki *KeyInfo) unmarshal(b []byte) error {
	for len(b) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			return err
		}
		b = rest
		if v.Class != 0 || v.IsCompound {
			continue
		}
		var ok bool
		switch v.Tag {
		case 1:
			if len(v.Bytes) != 1 {
				return fmt.Errorf("%w for algorithm", errUnexpectedLength)
			}
			if ki.Algorithm, ok = algorithmsMapInv[v.Bytes[0]]; !ok {
				return errUnsupportedAlgorithm
			}
		case 2:
			if len(v.Bytes) != 2 {
				return fmt.Errorf("%w for pin and touch policy", errUnexpectedLength)
			}
			if ki.PINPolicy, ok = pinPolicyMapInv[v.Bytes[0]]; !ok {
				return errUnsupportedPinPolicy
			}
			if ki.TouchPolicy, ok = touchPolicyMapInv[v.Bytes[1]]; !ok {
				return errUnsupportedTouchPolicy
			}
		case 3:
			if len(v.Bytes) != 1 {
				return fmt.Errorf("%w for origin", errUnexpectedLength)
			}
			if ki.Origin, ok = originMapInv[v.Bytes[0]]; !ok {
				return errUnsupportedOrigin
			}
		case 4:
			ki.PublicKey, err = decodePublic(v.Bytes, ki.Algorithm)
			if err != nil {
				return fmt.Errorf("failed to parse public key: %w", err)
			}
		default:
			// TODO: According to the Yubico website, we get two more fields,
			// if we pass 0x80 or 0x81 as slots:
			//     1. Default value (for PIN/PUK and management key): Whether the
			//        default value is used.
			//     2. Retries (for PIN/PUK): The number of retries remaining
			// However, it seems the reference implementation does not expect
			// these and can not parse them out:
			// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-2.3.1/lib/util.c#L1529
			// For now, we just ignore them.
		}
	}
	return nil
}

// KeyInfo returns public information about the given key slot. It is only
// supported by YubiKeys with a version >= 5.3.0.
func (yk *YubiKey) KeyInfo(slot Slot) (KeyInfo, error) {
	// https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html#_get_metadata
	cmd := apdu{
		instruction: insGetMetadata,
		param1:      0x00,
		param2:      byte(slot.Key),
	}
	resp, err := yk.tx.Transmit(cmd)
	if err != nil {
		return KeyInfo{}, fmt.Errorf("failed to execute command: %w", err)
	}
	var ki KeyInfo
	if err := ki.unmarshal(resp); err != nil {
		return KeyInfo{}, err
	}
	return ki, nil
}
