// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	func() {
		c, closeCard := newTestCard(t)
		defer closeCard()

		err := c.Reset()
		require.NoError(t, err, "Failed to reset applet")
	}()

	c, closeCard := newTestCard(t)
	defer closeCard()

	m, err := c.Metadata(DefaultPIN)
	assert.NoError(t, err, "Failed to get metadata")
	assert.Nil(t, m.ManagementKey, "Expected no management key set")

	wantKey := [24]byte{
		0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
		0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
		0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
	}

	m = &Metadata{
		ManagementKey: &wantKey,
	}

	err = c.SetMetadata(DefaultManagementKey, m)
	require.NoError(t, err, "Failed to set metadata")

	got, err := c.Metadata(DefaultPIN)
	require.NoError(t, err, "Failed to get metadata")
	require.NotNil(t, got.ManagementKey, "No management key")
	require.Equal(t, wantKey, *got.ManagementKey, "Wanted management key=0x%x, got=0x%x", wantKey, got.ManagementKey)
}

func TestMetadataUnmarshal(t *testing.T) {
	data, _ := hex.DecodeString("881a891809d98781fbdcc9b691a205806ec0ba8431ac0d9f59a500ad")
	wantKey := [24]byte{
		0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
		0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
		0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
	}
	var m Metadata

	err := m.unmarshal(data)
	require.NoError(t, err, "Failed to parse metadata")

	require.NotNil(t, m.ManagementKey, "No management key")

	gotKey := *m.ManagementKey
	assert.Equal(t, wantKey, gotKey)
}

func TestMetadataMarshal(t *testing.T) {
	key := [24]byte{
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
	m := Metadata{
		ManagementKey: &key,
	}

	got, err := m.marshal()
	require.NoError(t, err, "Failed to marshal key")
	assert.Equal(t, want, got)
}

func TestMetadataUpdate(t *testing.T) {
	key := [24]byte{
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

	m1 := Metadata{
		ManagementKey: &DefaultManagementKey,
	}
	raw, err := m1.marshal()
	require.NoError(t, err, "Failed to marshal key")

	m2 := Metadata{
		ManagementKey: &key,
		raw:           raw,
	}
	got, err := m2.marshal()
	require.NoError(t, err, "Failed to marshal updated metadata")
	assert.Equal(t, want, got)
}

func TestMetadataAdditionalFields(t *testing.T) {
	key := [24]byte{
		0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
		0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
		0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
	}
	raw := []byte{
		0x88,
		4,
		// Unrecognized sub-object. The key should be added, but this object
		// shouldn't be impacted.
		0x87,
		2,
		0x00,
		0x01,
	}

	want := append([]byte{
		0x88,
		30,
		// Unrecognized sub-object.
		0x87,
		2,
		0x00,
		0x01,
		// Added management key.
		0x89,
		24,
	}, key[:]...)

	m := Metadata{
		ManagementKey: &key,
		raw:           raw,
	}
	got, err := m.marshal()
	require.NoError(t, err, "Failed to marshal updated metadata")
	assert.Equal(t, want, got)
}
