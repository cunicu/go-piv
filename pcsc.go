// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"fmt"

	"github.com/ebfe/scard"
)

type apdu struct {
	instruction byte
	param1      byte
	param2      byte
	data        []byte
}

type scTx struct {
	*scard.Card
}

func newTx(h *scard.Card) (*scTx, error) {
	if err := h.BeginTransaction(); err != nil {
		return nil, err
	}

	return &scTx{
		Card: h,
	}, nil
}

func (t *scTx) Close() error {
	return t.Card.EndTransaction(scard.LeaveCard)
}

func (t *scTx) transmit(req []byte) (more bool, b []byte, err error) {
	resp, err := t.Card.Transmit(req)
	if err != nil {
		return false, nil, fmt.Errorf("failed to transmit request: %w", err)
	} else if len(resp) < 2 {
		return false, nil, fmt.Errorf("%w: want>=2B, got=%dB", errUnexpectedLength, len(resp))
	}
	sw1 := resp[len(resp)-2]
	sw2 := resp[len(resp)-1]
	if sw1 == 0x90 && sw2 == 0x00 {
		return false, resp[:len(resp)-2], nil
	}
	if sw1 == 0x61 {
		return true, resp[:len(resp)-2], nil
	}
	return false, nil, &apduError{sw1, sw2}
}

func (t *scTx) Transmit(d apdu) ([]byte, error) {
	data := d.data
	var resp []byte
	const maxAPDUDataSize = 0xff
	for len(data) > maxAPDUDataSize {
		req := make([]byte, 5+maxAPDUDataSize)
		req[0] = 0x10 // ISO/IEC 7816-4 5.1.1
		req[1] = d.instruction
		req[2] = d.param1
		req[3] = d.param2
		req[4] = 0xff
		copy(req[5:], data[:maxAPDUDataSize])
		data = data[maxAPDUDataSize:]
		_, r, err := t.transmit(req)
		if err != nil {
			return nil, fmt.Errorf("failed to transmit initial chunk %w", err)
		}
		resp = append(resp, r...)
	}

	req := make([]byte, 5+len(data))
	req[1] = d.instruction
	req[2] = d.param1
	req[3] = d.param2
	req[4] = byte(len(data))
	copy(req[5:], data)
	hasMore, r, err := t.transmit(req)
	if err != nil {
		return nil, err
	}
	resp = append(resp, r...)

	for hasMore {
		req := make([]byte, 5)
		req[1] = insGetResponseAPDU
		var r []byte
		hasMore, r, err = t.transmit(req)
		if err != nil {
			return nil, fmt.Errorf("failed to read further response: %w", err)
		}
		resp = append(resp, r...)
	}

	return resp, nil
}
