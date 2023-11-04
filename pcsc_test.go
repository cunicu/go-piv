// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"errors"
	"strings"
	"testing"

	"github.com/ebfe/scard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runContextTest(t *testing.T, f func(t *testing.T, c *scard.Context)) {
	ctx, err := scard.EstablishContext()
	require.NoError(t, err, "Failed to create context")

	defer func() {
		err := ctx.Release()
		assert.NoError(t, err, "Failed to close context")
	}()
	f(t, ctx)
}

func runHandleTest(t *testing.T, f func(t *testing.T, h *scard.Card)) {
	runContextTest(t, func(t *testing.T, c *scard.Context) {
		readers, err := c.ListReaders()
		if errors.Is(err, scard.ErrNoReadersAvailable) {
			err = nil // We ignore missing reader here
		}

		require.NoError(t, err, "Failed to list readers")

		reader := ""
		for _, r := range readers {
			if strings.Contains(strings.ToLower(r), "yubikey") {
				reader = r
				break
			}
		}
		if reader == "" {
			t.Skip("could not find YubiKey, skipping testing")
		}
		h, err := c.Connect(reader, scard.ShareExclusive, scard.ProtocolT1)
		require.NoError(t, err, "Failed to connect to %s: %v", reader, err)

		defer func() {
			err := h.Disconnect(scard.LeaveCard)
			assert.NoError(t, err, "Failed to disconnect from handle")
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
		require.NoError(t, err, "Failed to begin transaction")

		err = tx.Close()
		require.NoError(t, err, "Failed to close transaction")
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

	for _, test := range tests {
		err := &apduError{test.sw1, test.sw2}
		if errors.Is(err, ErrNotFound) != test.isErrNotFound {
			var s string
			if !test.isErrNotFound {
				s = " not"
			}
			t.Errorf("%q should %s be ErrNotFound", test.desc, s)
		}

		var authErr AuthError
		if errors.As(err, &authErr) != test.isAuthErr {
			var s string
			if !test.isAuthErr {
				s = " not"
			}
			t.Errorf("%q should %s be AuthErr", test.desc, s)
		}

		assert.Equal(t, authErr.Retries, test.retries)
		assert.ErrorContains(t, err, test.desc)
	}
}
