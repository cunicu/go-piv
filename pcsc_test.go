// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"errors"
	"strings"
	"testing"

	"github.com/ebfe/scard"
)

func runContextTest(t *testing.T, f func(t *testing.T, c *scard.Context)) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		t.Fatalf("creating context: %v", err)
	}
	defer func() {
		if err := ctx.Release(); err != nil {
			t.Errorf("closing context: %v", err)
		}
	}()
	f(t, ctx)
}

func runHandleTest(t *testing.T, f func(t *testing.T, h *scard.Card)) {
	runContextTest(t, func(t *testing.T, c *scard.Context) {
		readers, err := c.ListReaders()
		if err != nil && !errors.Is(err, scard.ErrNoReadersAvailable) {
			t.Fatalf("listing smart card readers: %v", err)
		}
		reader := ""
		for _, r := range readers {
			if strings.Contains(strings.ToLower(r), "yubikey") {
				reader = r
				break
			}
		}
		if reader == "" {
			t.Skip("could not find yubikey, skipping testing")
		}
		h, err := c.Connect(reader, scard.ShareExclusive, scard.ProtocolT1)
		if err != nil {
			t.Fatalf("connecting to %s: %v", reader, err)
		}
		defer func() {
			if err := h.Disconnect(scard.LeaveCard); err != nil {
				t.Errorf("disconnecting from handle: %v", err)
			}
		}()
		f(t, h)
	})
}

func TestHandle(t *testing.T) {
	runHandleTest(t, func(t *testing.T, h *scard.Card) {})
}

func TestTransaction(t *testing.T) {
	runHandleTest(t, func(t *testing.T, h *scard.Card) {
		tx, err := newTx(h)
		if err != nil {
			t.Fatalf("beginning transaction: %v", err)
		}
		if err := tx.Close(); err != nil {
			t.Fatalf("closing transaction: %v", err)
		}
	})
}

func TestErrors(t *testing.T) {
	tests := []struct {
		sw1, sw2      byte
		isErrNotFound bool
		isAuthErr     bool
		retries       int
		desc          string
	}{
		{0x68, 0x82, false, false, 0, "secure messaging not supported"},
		{0x63, 0x00, false, true, 0, "verification failed"},
		{0x63, 0xc0, false, true, 0, "verification failed (0 retries remaining)"},
		{0x63, 0xc1, false, true, 1, "verification failed (1 retry remaining)"},
		{0x63, 0xcf, false, true, 15, "verification failed (15 retries remaining)"},
		{0x63, 0x01, false, true, 1, "verification failed (1 retry remaining)"},
		{0x63, 0x0f, false, true, 15, "verification failed (15 retries remaining)"},
		{0x69, 0x83, false, true, 0, "authentication method blocked"},
		{0x6a, 0x82, true, false, 0, "data object or application not found"},
	}

	for _, tc := range tests {
		err := &apduErr{tc.sw1, tc.sw2}
		if errors.Is(err, ErrNotFound) != tc.isErrNotFound {
			var s string
			if !tc.isErrNotFound {
				s = " not"
			}
			t.Errorf("%q should%s be ErrNotFound", tc.desc, s)
		}

		var authErr AuthErr
		if errors.As(err, &authErr) != tc.isAuthErr {
			var s string
			if !tc.isAuthErr {
				s = " not"
			}
			t.Errorf("%q should%s be AuthErr", tc.desc, s)
		}
		if authErr.Retries != tc.retries {
			t.Errorf("%q retries should be %d, got %d", tc.desc, tc.retries, authErr.Retries)
		}
		if !strings.Contains(err.Error(), tc.desc) {
			t.Errorf("Error %v should contain text %v", err, tc.desc)
		}
	}
}