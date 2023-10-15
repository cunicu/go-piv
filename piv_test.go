// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto/rand"
	"errors"
	"flag"
	"io"
	"math/bits"
	"strings"
	"testing"

	"github.com/ebfe/scard"
)

// canModifyYubiKey indicates whether the test running has constented to
// destroying data on YubiKeys connected to the system.
//
//nolint:gochecknoglobals
var canModifyYubiKey = flag.Bool("reset-yubikey", false,
	"Flag required to run tests that access the yubikey")

func testGetVersion(t *testing.T, h *scard.Card) {
	tx, err := newTx(h)
	if err != nil {
		t.Fatalf("new transaction: %v", err)
	}
	defer tx.Close()
	if err := ykSelectApplication(tx, aidPIV[:]); err != nil {
		t.Fatalf("selecting application: %v", err)
	}
	if _, err := ykVersion(tx); err != nil {
		t.Fatalf("listing version: %v", err)
	}
}

//nolint:unparam
func testRequiresVersion(t *testing.T, yk *YubiKey, major, minor, patch int) {
	v := yk.Version()
	if !supportsVersion(v, major, minor, patch) {
		t.Skipf("test requires yubikey version %d.%d.%d: got=%d.%d.%d", major, minor, patch, v.Major, v.Minor, v.Patch)
	}
}

func TestGetVersion(t *testing.T) { runHandleTest(t, testGetVersion) }

func TestCards(t *testing.T) {
	if _, err := Cards(); err != nil {
		t.Fatalf("listing cards: %v", err)
	}
}

func newTestYubiKey(t *testing.T) (*YubiKey, func()) {
	cards, err := Cards()
	if err != nil {
		t.Fatalf("listing cards: %v", err)
	}
	for _, card := range cards {
		if !strings.Contains(strings.ToLower(card), "yubikey") {
			continue
		}
		if !*canModifyYubiKey {
			t.Skip("not running test that accesses yubikey, provide --reset-yubikey flag")
		}
		yk, err := Open(card)
		if err != nil {
			t.Fatalf("getting new yubikey: %v", err)
		}
		return yk, func() {
			if err := yk.Close(); err != nil {
				t.Errorf("closing yubikey: %v", err)
			}
		}
	}
	t.Skip("no yubikeys detected, skipping")
	return nil, nil
}

func TestNewYubiKey(t *testing.T) {
	_, closeCard := newTestYubiKey(t)
	defer closeCard()
}

func TestMultipleConnections(t *testing.T) {
	cards, err := Cards()
	if err != nil {
		t.Fatalf("listing cards: %v", err)
	}
	for _, card := range cards {
		if !strings.Contains(strings.ToLower(card), "yubikey") {
			continue
		}
		if !*canModifyYubiKey {
			t.Skip("not running test that accesses yubikey, provide --reset-yubikey flag")
		}
		yk, err := Open(card)
		if err != nil {
			t.Fatalf("getting new yubikey: %v", err)
		}
		defer func() {
			if err := yk.Close(); err != nil {
				t.Errorf("closing yubikey: %v", err)
			}
		}()

		_, oerr := Open(card)
		if oerr == nil {
			t.Fatalf("expected second open operation to fail")
		}
		var e scard.Error
		if !errors.As(oerr, &e) {
			t.Fatalf("expected scard.Error, got %T", oerr)
		}
		if !errors.Is(e, scard.ErrSharingViolation) {
			t.Fatalf("expected return code 0x8010000B (sharing vialation), got=0x%x", e)
		}
		return
	}
	t.Skip("no yubikeys detected, skipping")
}

func TestYubiKeySerial(t *testing.T) {
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()

	if _, err := yk.Serial(); err != nil {
		t.Fatalf("getting serial number: %v", err)
	}
}

func TestYubiKeyLoginNeeded(t *testing.T) {
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()

	testRequiresVersion(t, yk, 4, 3, 0)

	if !ykLoginNeeded(yk.tx) {
		t.Errorf("expected login needed")
	}
	if err := ykLogin(yk.tx, DefaultPIN); err != nil {
		t.Fatalf("login: %v", err)
	}
	if ykLoginNeeded(yk.tx) {
		t.Errorf("expected no login needed")
	}
}

func TestYubiKeyPINRetries(t *testing.T) {
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()
	retries, err := yk.Retries()
	if err != nil {
		t.Fatalf("getting retries: %v", err)
	}
	if retries < 0 || retries > 15 {
		t.Fatalf("invalid number of retries: %d", retries)
	}
}

func TestYubiKeyReset(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()
	if err := yk.Reset(); err != nil {
		t.Fatalf("resetting yubikey: %v", err)
	}
	if err := yk.VerifyPIN(DefaultPIN); err != nil {
		t.Fatalf("login: %v", err)
	}
}

func TestYubiKeyLogin(t *testing.T) {
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()

	if err := yk.VerifyPIN(DefaultPIN); err != nil {
		t.Fatalf("login: %v", err)
	}
}

func TestYubiKeyAuthenticate(t *testing.T) {
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()

	if err := yk.authManagementKey(DefaultManagementKey); err != nil {
		t.Errorf("authenticating: %v", err)
	}
}

func TestYubiKeySetManagementKey(t *testing.T) {
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()

	var mgmtKey [24]byte
	if _, err := io.ReadFull(rand.Reader, mgmtKey[:]); err != nil {
		t.Fatalf("generating management key: %v", err)
	}

	if err := yk.SetManagementKey(DefaultManagementKey, mgmtKey); err != nil {
		t.Fatalf("setting management key: %v", err)
	}
	if err := yk.authManagementKey(mgmtKey); err != nil {
		t.Errorf("authenticating with new management key: %v", err)
	}
	if err := yk.SetManagementKey(mgmtKey, DefaultManagementKey); err != nil {
		t.Fatalf("resetting management key: %v", err)
	}
}

func TestYubiKeyUnblockPIN(t *testing.T) {
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()

	badPIN := "0"
	for {
		err := ykLogin(yk.tx, badPIN)
		if err == nil {
			t.Fatalf("login with bad pin succeeded")
		}
		var e AuthError
		if !errors.As(err, &e) {
			t.Fatalf("error returned was not a wrong pin error: %v", err)
		}
		if e.Retries == 0 {
			break
		}
	}

	if err := yk.Unblock(DefaultPUK, DefaultPIN); err != nil {
		t.Fatalf("unblocking pin: %v", err)
	}
	if err := ykLogin(yk.tx, DefaultPIN); err != nil {
		t.Errorf("failed to login with pin after unblock: %v", err)
	}
}

func TestYubiKeyChangePIN(t *testing.T) {
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()

	newPIN := "654321"
	if err := yk.SetPIN(newPIN, newPIN); err == nil {
		t.Errorf("successfully changed pin with invalid pin, expected error")
	}
	if err := yk.SetPIN(DefaultPIN, newPIN); err != nil {
		t.Fatalf("changing pin: %v", err)
	}
	if err := yk.SetPIN(newPIN, DefaultPIN); err != nil {
		t.Fatalf("resetting pin: %v", err)
	}
}

func TestYubiKeyChangePUK(t *testing.T) {
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()

	newPUK := "87654321"
	if err := yk.SetPUK(newPUK, newPUK); err == nil {
		t.Errorf("successfully changed puk with invalid puk, expected error")
	}
	if err := yk.SetPUK(DefaultPUK, newPUK); err != nil {
		t.Fatalf("changing puk: %v", err)
	}
	if err := yk.SetPUK(newPUK, DefaultPUK); err != nil {
		t.Fatalf("resetting puk: %v", err)
	}
}

func TestChangeManagementKey(t *testing.T) {
	yk, closeCard := newTestYubiKey(t)
	defer closeCard()

	var newKey [24]byte
	if _, err := io.ReadFull(rand.Reader, newKey[:]); err != nil {
		t.Fatalf("generating new management key: %v", err)
	}
	// Apply odd-parity
	for i, b := range newKey {
		if bits.OnesCount8(b)%2 == 0 {
			newKey[i] = b ^ 1 // flip least significant bit
		}
	}
	if err := yk.SetManagementKey(newKey, newKey); err == nil {
		t.Errorf("successfully changed management key with invalid key, expected error")
	}
	if err := yk.SetManagementKey(DefaultManagementKey, newKey); err != nil {
		t.Fatalf("changing management key: %v", err)
	}
	if err := yk.SetManagementKey(newKey, DefaultManagementKey); err != nil {
		t.Fatalf("resetting management key: %v", err)
	}
}
