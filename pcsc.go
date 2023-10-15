// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"errors"
	"fmt"

	"github.com/ebfe/scard"
)

// AuthError is an error indicating an authentication error occurred (wrong PIN or blocked).
type AuthError struct {
	// Retries is the number of retries remaining if this error resulted from a retry-able
	// authentication attempt.  If the authentication method is blocked or does not support
	// retries, this will be 0.
	Retries int
}

func (v AuthError) Error() string {
	r := "retries"
	if v.Retries == 1 {
		r = "retry"
	}
	return fmt.Sprintf("verification failed (%d %s remaining)", v.Retries, r)
}

// ErrNotFound is returned when the requested object on the smart card is not found.
var ErrNotFound = errors.New("data object or application not found")

// apduError is an error interacting with the PIV application on the smart card.
// This error may wrap more accessible errors, like ErrNotFound or an instance
// of AuthErr, so callers are encouraged to use errors.Is and errors.As for
// these common cases.
type apduError struct {
	sw1 byte
	sw2 byte
}

// Status returns the Status Word returned by the card command.
func (a *apduError) Status() uint16 {
	return uint16(a.sw1)<<8 | uint16(a.sw2)
}

func (a *apduError) Error() string {
	var msg string
	if u := a.Unwrap(); u != nil {
		msg = u.Error()
	}

	switch a.Status() {
	// 0x6300 is "verification failed", represented as AuthErr{0}
	// 0x63Cn is "verification failed" with retry, represented as AuthErr{n}
	case 0x6882:
		msg = "secure messaging not supported"
	case 0x6982:
		msg = "security status not satisfied"
	case 0x6983:
		// This will also be AuthErr{0} but we override the message here
		// so that it's clear that the reason is a block rather than a simple
		// failed authentication verification.
		msg = "authentication method blocked"
	case 0x6987:
		msg = "expected secure messaging data objects are missing"
	case 0x6988:
		msg = "secure messaging data objects are incorrect"
	case 0x6a80:
		msg = "incorrect parameter in command data field"
	case 0x6a81:
		msg = "function not supported"
	// 0x6a82 is "data object or application not found" aka ErrNotFound
	case 0x6a84:
		msg = "not enough memory"
	case 0x6a86:
		msg = "incorrect parameter in P1 or P2"
	case 0x6a88:
		msg = "referenced data or reference data not found"
	}

	if msg != "" {
		msg = ": " + msg
	}
	return fmt.Sprintf("smart card error %04x%s", a.Status(), msg)
}

// Unwrap retrieves an accessible error type, if able.
func (a *apduError) Unwrap() error {
	st := a.Status()
	switch {
	case st == 0x6a82:
		return ErrNotFound
	case st == 0x6300:
		return AuthError{0}
	case st == 0x6983:
		return AuthError{0}
	case st&0xfff0 == 0x63c0:
		return AuthError{int(st & 0xf)}
	case st&0xfff0 == 0x6300:
		// Older YubiKeys sometimes return sw1=0x63 and sw2=0x0N to indicate the
		// number of retries. This isn't spec compliant, but support it anyway.
		//
		// https://cunicu.li/go-piv/issues/60
		return AuthError{int(st & 0xf)}
	}
	return nil
}

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
		return false, nil, fmt.Errorf("transmitting request: %w", err)
	} else if len(resp) < 2 {
		return false, nil, fmt.Errorf("scard response too short: %d", len(resp))
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
			return nil, fmt.Errorf("transmitting initial chunk %w", err)
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
			return nil, fmt.Errorf("reading further response: %w", err)
		}
		resp = append(resp, r...)
	}

	return resp, nil
}
