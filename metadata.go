// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Metadata holds protected metadata. This is primarily used by YubiKey manager
// to implement PIN protect management keys, storing management keys on the card
// guarded by the PIN.
type Metadata struct {
	// ManagementKey is the management key stored directly on the YubiKey.
	ManagementKey *[24]byte

	// raw, if not nil, is the full bytes
	raw []byte
}

func (m *Metadata) marshal() ([]byte, error) {
	if m.raw == nil {
		if m.ManagementKey == nil {
			return []byte{0x88, 0x00}, nil
		}
		return append([]byte{
			0x88,
			26,
			0x89,
			24,
		}, m.ManagementKey[:]...), nil
	}

	if m.ManagementKey == nil {
		return m.raw, nil
	}

	var metadata asn1.RawValue
	if _, err := asn1.Unmarshal(m.raw, &metadata); err != nil {
		return nil, fmt.Errorf("failed to update metadata: %w", err)
	}
	if !bytes.HasPrefix(metadata.FullBytes, []byte{0x88}) {
		return nil, fmt.Errorf("%w: 0x88", errExpectedTag)
	}
	raw := metadata.Bytes

	metadata.Bytes = nil
	metadata.FullBytes = nil

	for len(raw) > 0 {
		var (
			err error
			v   asn1.RawValue
		)
		raw, err = asn1.Unmarshal(raw, &v)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata field: %w", err)
		}

		if bytes.HasPrefix(v.FullBytes, []byte{0x89}) {
			continue
		}
		metadata.Bytes = append(metadata.Bytes, v.FullBytes...)
	}
	metadata.Bytes = append(metadata.Bytes, 0x89, 24)
	metadata.Bytes = append(metadata.Bytes, m.ManagementKey[:]...)
	return asn1.Marshal(metadata)
}

func (m *Metadata) unmarshal(b []byte) error {
	m.raw = b
	var md asn1.RawValue
	if _, err := asn1.Unmarshal(b, &md); err != nil {
		return err
	}
	if !bytes.HasPrefix(md.FullBytes, []byte{0x88}) {
		return fmt.Errorf("%w: 0x88", errExpectedTag)
	}
	d := md.Bytes
	for len(d) > 0 {
		var (
			err error
			v   asn1.RawValue
		)
		d, err = asn1.Unmarshal(d, &v)
		if err != nil {
			return fmt.Errorf("failed to unmarshal metadata field: %w", err)
		}
		if !bytes.HasPrefix(v.FullBytes, []byte{0x89}) {
			continue
		}
		// 0x89 indicates key
		if len(v.Bytes) != 24 {
			return fmt.Errorf("%w for management key: got=%dB, want=24B", errUnexpectedLength, len(v.Bytes))
		}
		var key [24]byte
		copy(key[:], v.Bytes)
		m.ManagementKey = &key
	}
	return nil
}

// Metadata returns protected data stored on the card. This can be used to
// retrieve PIN protected management keys.
func (c *Card) Metadata(pin string) (*Metadata, error) {
	// NOTE: for some reason this action requires the PIN to be authenticated on
	// the same transaction. It doesn't work otherwise.
	if err := login(c.tx, pin); err != nil {
		return nil, fmt.Errorf("failed to authenticate with PIN: %w", err)
	}
	cmd := apdu{
		instruction: insGetData,
		param1:      0x3f,
		param2:      0xff,
		data: []byte{
			0x5c, // Tag list
			0x03,
			0x5f,
			0xc1,
			0x09,
		},
	}
	resp, err := c.tx.Transmit(cmd)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return &Metadata{}, nil
		}
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}
	obj, _, err := unmarshalASN1(resp, 1, 0x13) // tag 0x53
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	m := &Metadata{}
	if err := m.unmarshal(obj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal protected metadata: %w", err)
	}
	return m, nil
}

// SetMetadata sets PIN protected metadata on the key. This is primarily to
// store the management key on the smart card instead of managing the PIN and
// management key separately.
func (c *Card) SetMetadata(key [24]byte, m *Metadata) error {
	data, err := m.marshal()
	if err != nil {
		return fmt.Errorf("failed to encode metadata: %w", err)
	}
	data = append([]byte{
		0x5c, // Tag list
		0x03,
		0x5f,
		0xc1,
		0x09,
	}, marshalASN1(0x53, data)...)
	cmd := apdu{
		instruction: insPutData,
		param1:      0x3f,
		param2:      0xff,
		data:        data,
	}
	// NOTE: for some reason this action requires the management key authenticated
	// on the same transaction. It doesn't work otherwise.
	if err := authenticate(c.tx, key, rand.Reader); err != nil {
		return fmt.Errorf("failed to authenticate with key: %w", err)
	}
	if _, err := c.tx.Transmit(cmd); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}
	return nil
}
