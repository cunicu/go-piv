// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"errors"
	"fmt"

	"cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/encoding/tlv"
)

// PinProtectedData holds PIN protected data. This is primarily used by YubiKey manager
// to implement PIN protect management keys, storing management keys on the card
// guarded by the PIN.
type PinProtectedData struct {
	tlv.TagValues
}

func (d PinProtectedData) ManagementKey() (k ManagementKey, err error) {
	tv, _, ok := d.Get(0x88)
	if !ok {
		return ManagementKey{}, ErrNotFound
	}

	// Nested recording as tag 0x88 is not constructed
	// This might have been a mistake by Yubico?
	tvsYubico, err := tlv.DecodeBER(tv)
	if err != nil {
		return k, err
	}

	key, _, ok := tvsYubico.Get(0x89)
	if !ok {
		return k, ErrNotFound
	}

	if len(key) != len(DefaultManagementKey) {
		return ManagementKey{}, errInvalidManagementKeyLength
	}

	return ManagementKey(key), nil
}

func (d *PinProtectedData) SetManagementKey(key ManagementKey) error {
	var tvYubico tlv.TagValue
	if tvs := d.PopAll(0x88); len(tvs) == 0 {
		tvYubico = tlv.New(0x88)
	} else if len(tvs) > 1 {
		return fmt.Errorf("%w: found more then one YubiKey pin protected tag value", errUnmarshal)
	} else {
		tvYubico = tvs[0]
	}

	tvsYubico, err := tlv.DecodeBER(tvYubico.Value)
	if err != nil {
		return err
	}

	// Remove previous management key
	tvsYubico.DeleteAll(0x89)
	// Add new management key
	tvsYubico.Put(tlv.New(0x89, key[:]))

	if tvYubico.Value, err = tlv.EncodeBER(tvsYubico...); err != nil {
		return err
	}

	d.Put(tvYubico)

	return nil
}

// PinProtectedData returns protected data stored on the card. This can be used to
// retrieve PIN protected management keys.
func (c *Card) PinProtectedData(pin string) (*PinProtectedData, error) {
	// NOTE: for some reason this action requires the PIN to be authenticated on
	// the same transaction. It doesn't work otherwise.
	if err := login(c.tx, pin); err != nil {
		return nil, fmt.Errorf("failed to authenticate with PIN: %w", err)
	}

	resp, err := sendTLV(c.tx, insGetData, 0x3f, 0xff, doPrinted.TagValue())
	if err != nil {
		if errors.Is(err, iso7816.ErrFileOrAppNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}

	v, _, ok := resp.Get(0x53)
	if !ok {
		return nil, errUnmarshal
	}

	ppd, err := tlv.DecodeBER(v)
	if err != nil {
		return nil, errUnmarshal
	}

	return &PinProtectedData{ppd}, nil
}

// SetMetadata sets PIN protected metadata on the key. This is primarily to
// store the management key on the smart card instead of managing the PIN and
// management key separately.
func (c *Card) SetPinProtectedData(key ManagementKey, ppd *PinProtectedData) error {
	// NOTE: for some reason this action requires the management key authenticated
	// on the same transaction. It doesn't work otherwise.
	if err := c.authenticate(key); err != nil {
		return fmt.Errorf("failed to authenticate with key: %w", err)
	}

	ppdData, err := tlv.EncodeBER(ppd.TagValues...)
	if err != nil {
		return err
	}

	if _, err := sendTLV(c.tx, insPutData, 0x3f, 0xff,
		doPrinted.TagValue(),
		tlv.New(0x53, ppdData),
	); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	return nil
}
