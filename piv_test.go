// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"runtime"
	"testing"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/drivers/pcsc"
	"cunicu.li/go-iso7816/filter"
	"cunicu.li/go-iso7816/test"
	"github.com/ebfe/scard"
	"github.com/stretchr/testify/require"
)

func TestGetVersion(t *testing.T) {
	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		require.NotNil(t, c.version)
	})
}

// constReader is an io.Reader yielding only null-bytes
// We use it as a random number generator for tests
// as we need a deterministic test outputs to satisfy
// the expected method call by your mocked smart-card.
//
// See: https://github.com/golang/go/issues/38548
type constReader struct{}

func (r *constReader) Read(p []byte) (int, error) {
	for i := 0; i < len(p); i++ {
		p[i] = 0xab
	}
	return len(p), nil
}

func withCard(t *testing.T, reset, long bool, extraFilter filter.Filter, cb func(t *testing.T, c *Card)) {
	if long && testing.Short() {
		t.Skip("skipping test in short mode")
	}

	flt := filter.HasApplet(iso.AidPIV)

	if extraFilter != nil {
		flt = filter.And(flt, extraFilter)
	}

	test.WithCard(t, flt, func(t *testing.T, c *iso.Card) {
		require := require.New(t)

		pivCard, err := NewCard(c)
		require.NoError(err)

		// Fix random number generator for reproducible tests
		// pivCard.Rand = rand.New(rand.NewSource(42)) //nolint:gosec
		pivCard.Rand = &constReader{}

		if reset {
			err = pivCard.Reset()
			require.NoError(err)
		}

		cb(t, pivCard)

		err = pivCard.Close()
		require.NoError(err)
	})
}

func TestNewCard(t *testing.T) {
	withCard(t, false, false, nil, func(_ *testing.T, _ *Card) {})
}

func TestMultipleConnections(t *testing.T) {
	require := require.New(t)

	if !test.DangerousWipeRealCard || runtime.GOOS == "darwin" {
		t.Skip("not running test that accesses card, please set env var TEST_DANGEROUS_WIPE_REAL_CARD=1")
	}

	ctx, err := scard.EstablishContext()
	require.NoError(err)

	defer func() {
		err = ctx.Release()
		require.NoError(err)
	}()

	c1, err := pcsc.OpenFirstCard(ctx, filter.HasApplet(iso.AidPIV), false)
	require.NoError(err)

	defer c1.Close()

	_, err = pcsc.OpenFirstCard(ctx, filter.HasApplet(iso.AidPIV), false)
	require.Error(err)
}

func TestSerial(t *testing.T) {
	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		_, err := c.Serial()
		require.NoError(t, err, "Failed to get serial number")
	})
}

func TestReset(t *testing.T) {
	withCard(t, false, true, nil, func(t *testing.T, c *Card) {
		err := c.Reset()
		require.NoError(t, err, "Failed to reset card")

		err = c.VerifyPIN(DefaultPIN)
		require.NoError(t, err, "Failed to verify PIN")
	})
}
