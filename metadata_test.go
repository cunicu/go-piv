// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	func() {
		c, closeCard := newTestCard(t)
		defer closeCard()
		if err := c.Reset(); err != nil {
			t.Fatalf("resetting card: %v", err)
		}
	}()

	c, closeCard := newTestCard(t)
	defer closeCard()

	if m, err := c.Metadata(DefaultPIN); err != nil {
		t.Errorf("getting metadata: %v", err)
	} else if m.ManagementKey != nil {
		t.Errorf("expected no management key set")
	}

	wantKey := [24]byte{
		0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
		0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
		0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
	}
	m := &Metadata{
		ManagementKey: &wantKey,
	}
	if err := c.SetMetadata(DefaultManagementKey, m); err != nil {
		t.Fatalf("setting metadata: %v", err)
	}
	got, err := c.Metadata(DefaultPIN)
	if err != nil {
		t.Fatalf("getting metadata: %v", err)
	}
	if got.ManagementKey == nil {
		t.Errorf("no management key")
	} else if *got.ManagementKey != wantKey {
		t.Errorf("wanted management key=0x%x, got=0x%x", wantKey, got.ManagementKey)
	}
}

func TestMetadataUnmarshal(t *testing.T) {
	data, _ := hex.DecodeString("881a891809d98781fbdcc9b691a205806ec0ba8431ac0d9f59a500ad")
	wantKey := [24]byte{
		0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
		0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
		0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
	}
	var m Metadata
	if err := m.unmarshal(data); err != nil {
		t.Fatalf("parsing metadata: %v", err)
	}
	if m.ManagementKey == nil {
		t.Fatalf("no management key")
	}
	gotKey := *m.ManagementKey
	if gotKey != wantKey {
		t.Errorf("(*Metadata).unmarshal, got key=0x%x, want key=0x%x", gotKey, wantKey)
	}
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
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("(*Metadata.marshal, got=0x%x, want=0x%x", got, want)
	}
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
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	m2 := Metadata{
		ManagementKey: &key,
		raw:           raw,
	}
	got, err := m2.marshal()
	if err != nil {
		t.Fatalf("marshaling updated metadata: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("(*Metadata.marshal, got=0x%x, want=0x%x", got, want)
	}
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
	if err != nil {
		t.Fatalf("marshaling updated metadata: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("(*Metadata.marshal, got=0x%x, want=0x%x", got, want)
	}
}
