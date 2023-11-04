// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto/rand"
	"flag"
	"io"
	"math/bits"
	"strings"
	"testing"

	"github.com/ebfe/scard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// canModifyCard indicates whether the test running has consented to
// destroying data on YubiKeys connected to the system.
//
//nolint:gochecknoglobals
var canModifyCard = flag.Bool("reset-card", false,
	"Flag required to run tests that access the smart card")

func testGetVersion(t *testing.T, h *scard.Card) {
	tx, err := newTx(h)
	require.NoError(t, err, "Failed to begin new transaction")

	defer tx.Close()

	err = selectApplication(tx, aidPIV[:])
	require.NoError(t, err, "Failed to select application")

	_, err = getVersion(tx)
	require.NoError(t, err, "Failed to list version")
}

//nolint:unparam
func testRequiresVersion(t *testing.T, c *Card, major, minor, patch int) {
	v := c.Version()
	if !supportsVersion(v, major, minor, patch) {
		t.Skipf("test requires YubiKey version %d.%d.%d: got=%d.%d.%d", major, minor, patch, v.Major, v.Minor, v.Patch)
	}
}

func TestGetVersion(t *testing.T) {
	runHandleTest(t, testGetVersion)
}

func TestCards(t *testing.T) {
	_, err := Cards()
	require.NoError(t, err, "Failed to list cards")
}

func newTestCard(t *testing.T) (*Card, func()) {
	cards, err := Cards()
	require.NoError(t, err, "Failed to list cards")

	for _, card := range cards {
		if !strings.Contains(strings.ToLower(card), "yubikey") {
			continue
		}
		if !*canModifyCard {
			t.Skip("not running test that accesses card, provide --reset-card flag")
		}
		c, err := Open(card)
		require.NoError(t, err, "Failed to get new card")

		return c, func() {
			err := c.Close()
			assert.NoError(t, err, "Failed to close card")
		}
	}
	t.Skip("no YubiKeys detected, skipping")
	return nil, nil
}

func TestNewCard(t *testing.T) {
	_, closeCard := newTestCard(t)
	defer closeCard()
}

func TestMultipleConnections(t *testing.T) {
	cards, err := Cards()
	require.NoError(t, err, "Failed to list cards")

	if !*canModifyCard {
		t.Skip("not running test that accesses card, provide --reset-card flag")
	}

	for _, card := range cards {
		if !strings.Contains(strings.ToLower(card), "yubikey") {
			continue
		}

		c, err := Open(card)
		require.NoError(t, err, "Failed to get new card")

		defer func() {
			err := c.Close()
			require.NoError(t, err, "Failed to close card")
		}()

		_, err = Open(card)
		require.Error(t, err, "Expected second open operation to fail")

		var sErr scard.Error
		require.ErrorAs(t, err, &sErr, "Expected scard.Error, got %T", err)
		require.ErrorIs(t, sErr, scard.ErrSharingViolation, "Expected return code 0x8010000B (sharing violation), got=0x%x", sErr)

		return
	}

	t.Skip("no YubiKey detected, skipping")
}

func TestSerial(t *testing.T) {
	c, closeCard := newTestCard(t)
	defer closeCard()

	_, err := c.Serial()
	require.NoError(t, err, "Failed to get serial number")
}

func TestLoginNeeded(t *testing.T) {
	c, closeCard := newTestCard(t)
	defer closeCard()

	testRequiresVersion(t, c, 4, 3, 0)

	assert.True(t, loginNeeded(c.tx), "Expected login needed")

	err := login(c.tx, DefaultPIN)
	require.NoError(t, err, "Failed to login")

	needed := loginNeeded(c.tx)
	require.False(t, needed, "Expected no login needed")
}

func TestPINRetries(t *testing.T) {
	c, closeCard := newTestCard(t)
	defer closeCard()

	retries, err := c.Retries()
	require.NoError(t, err, "Failed to get retries")

	require.Less(t, retries, 15, "Invalid number of retries: %d", retries)
	require.LessOrEqual(t, 0, retries, "Invalid number of retries: %d", retries)
}

func TestReset(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	c, closeCard := newTestCard(t)
	defer closeCard()

	err := c.Reset()
	require.NoError(t, err, "Failed to reset card")

	err = c.VerifyPIN(DefaultPIN)
	require.NoError(t, err, "Failed to verify PIN")
}

func TestLogin(t *testing.T) {
	c, closeCard := newTestCard(t)
	defer closeCard()

	err := c.VerifyPIN(DefaultPIN)
	require.NoError(t, err, "Failed to login")
}

func TestAuthenticate(t *testing.T) {
	c, closeCard := newTestCard(t)
	defer closeCard()

	err := c.authManagementKey(DefaultManagementKey)
	assert.NoError(t, err, "Failed to authenticate")
}

func TestSetManagementKey(t *testing.T) {
	c, closeCard := newTestCard(t)
	defer closeCard()

	var mgmtKey [24]byte
	_, err := io.ReadFull(rand.Reader, mgmtKey[:])
	require.NoError(t, err, "Failed to generate management key")

	err = c.SetManagementKey(DefaultManagementKey, mgmtKey)
	require.NoError(t, err, "Failed to set management key")

	err = c.authManagementKey(mgmtKey)
	assert.NoError(t, err, "Failed to authenticate with new management key")

	err = c.SetManagementKey(mgmtKey, DefaultManagementKey)
	require.NoError(t, err, "Failed to reset management key")
}

func TestUnblockPIN(t *testing.T) {
	c, closeCard := newTestCard(t)
	defer closeCard()

	badPIN := "0"
	for {
		err := login(c.tx, badPIN)
		require.Error(t, err, "Login with bad pin succeeded")

		var e AuthError
		require.ErrorAs(t, err, &e, "Error returned was not a wrong pin error")

		if e.Retries == 0 {
			break
		}
	}

	err := c.Unblock(DefaultPUK, DefaultPIN)
	require.NoError(t, err, "Failed to unblock PIN")

	err = login(c.tx, DefaultPIN)
	assert.NoError(t, err, "Failed to login with pin after unblock")
}

func TestChangePIN(t *testing.T) {
	c, closeCard := newTestCard(t)
	defer closeCard()

	newPIN := "654321"

	err := c.SetPIN(newPIN, newPIN)
	assert.Error(t, err, "Successfully changed pin with invalid pin, expected error")

	err = c.SetPIN(DefaultPIN, newPIN)
	require.NoError(t, err, "Failed to change PIN")

	err = c.SetPIN(newPIN, DefaultPIN)
	require.NoError(t, err, "Failed to reset PIN")
}

func TestChangePUK(t *testing.T) {
	c, closeCard := newTestCard(t)
	defer closeCard()

	newPUK := "87654321"

	err := c.SetPUK(newPUK, newPUK)
	assert.Error(t, err, "Successfully changed puk with invalid puk, expected error")

	err = c.SetPUK(DefaultPUK, newPUK)
	require.NoError(t, err, "Failed to changing PUK")

	err = c.SetPUK(newPUK, DefaultPUK)
	require.NoError(t, err, "Failed to reset PUK")
}

func TestChangeManagementKey(t *testing.T) {
	c, closeCard := newTestCard(t)
	defer closeCard()

	var newKey [24]byte
	_, err := io.ReadFull(rand.Reader, newKey[:])
	require.NoError(t, err, "Failed to generate new management key")

	// Apply odd-parity
	for i, b := range newKey {
		if bits.OnesCount8(b)%2 == 0 {
			newKey[i] = b ^ 1 // flip least significant bit
		}
	}

	err = c.SetManagementKey(newKey, newKey)
	assert.Error(t, err, "Successfully changed management key with invalid key, expected error")

	err = c.SetManagementKey(DefaultManagementKey, newKey)
	require.NoError(t, err, "Failed to change management key")

	err = c.SetManagementKey(newKey, DefaultManagementKey)
	require.NoError(t, err, "Failed to reset management key")
}
