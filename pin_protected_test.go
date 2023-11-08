// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"encoding/hex"
	"testing"

	"cunicu.li/go-iso7816/encoding/tlv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPinProtected(t *testing.T) {
	withCard(t, true, true, nil, func(t *testing.T, c *Card) {
		_, err := c.PinProtectedData(DefaultPIN)
		assert.ErrorIs(t, err, ErrNotFound, "A card should return no PPD after reset")

		wantKey := ManagementKey{
			0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
			0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
			0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
		}

		ppd := &PinProtectedData{}
		err = ppd.SetManagementKey(wantKey)
		require.NoError(t, err)

		err = c.SetPinProtectedData(DefaultManagementKey, ppd)
		require.NoError(t, err, "Failed to set metadata")

		got, err := c.PinProtectedData(DefaultPIN)
		require.NoError(t, err, "Failed to get PIN protected data")

		gotKey, err := got.ManagementKey()
		require.NoError(t, err)

		require.Equal(t, wantKey, gotKey, "Wanted management key=0x%x, got=0x%x", wantKey, gotKey)
	})
}

func TestPinProtectedUnmarshal(t *testing.T) {
	data, _ := hex.DecodeString("881a891809d98781fbdcc9b691a205806ec0ba8431ac0d9f59a500ad")
	wantKey := ManagementKey{
		0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
		0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
		0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
	}

	tvs, err := tlv.DecodeBER(data)
	require.NoError(t, err)

	ppd := PinProtectedData{tvs}

	gotKey, err := ppd.ManagementKey()
	require.NoError(t, err)

	assert.Equal(t, wantKey, gotKey)
}

func TestPinProtectedMarshal(t *testing.T) {
	key := ManagementKey{
		0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
		0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
		0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
	}
	want := append([]byte{
		0x88,
		26,
		0x89,
		24,
	}, key[:]...)

	ppd := PinProtectedData{}

	err := ppd.SetManagementKey(key)
	require.NoError(t, err)

	got, err := tlv.EncodeBER(ppd.TagValues...)
	require.NoError(t, err, "Failed to marshal key")
	assert.Equal(t, want, got)
}

func TestPinProtectedUpdate(t *testing.T) {
	key := ManagementKey{
		0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
		0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
		0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
	}
	want := append([]byte{
		0x88,
		26,
		0x89,
		24,
	}, key[:]...)

	ppd := PinProtectedData{}

	err := ppd.SetManagementKey(DefaultManagementKey)
	require.NoError(t, err)

	k1, err := ppd.ManagementKey()
	require.NoError(t, err)
	require.Equal(t, DefaultManagementKey, k1)

	err = ppd.SetManagementKey(key)
	require.NoError(t, err)

	k2, err := ppd.ManagementKey()
	require.NoError(t, err)
	require.Equal(t, key, k2)

	got, err := tlv.EncodeBER(ppd.TagValues...)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

// func TestPinProtectedAdditionalFields(t *testing.T) {
// 	key := ManagementKey{
// 		0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
// 		0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
// 		0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
// 	}
// 	raw := []byte{
// 		0x88,
// 		4,
// 		// Unrecognized sub-object. The key should be added, but this object
// 		// shouldn't be impacted.
// 		0x87,
// 		2,
// 		0x00,
// 		0x01,
// 	}

// 	want := append([]byte{
// 		0x88,
// 		30,
// 		// Unrecognized sub-object.
// 		0x87,
// 		2,
// 		0x00,
// 		0x01,
// 		// Added management key.
// 		0x89,
// 		24,
// 	}, key[:]...)

// 	m := PinProtectedData{
// 		ManagementKey: &key,
// 		raw:           raw,
// 	}
// 	got, err := m.marshal()
// 	require.NoError(t, err, "Failed to marshal updated metadata")
// 	assert.Equal(t, want, got)
// }
