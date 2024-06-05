// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"io"
	"math/bits"
	"testing"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/devices/yubikey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginNeeded(t *testing.T) {
	v, _ := iso.ParseVersion("4.3.0")
	withCard(t, false, false, yubikey.HasVersion(v), func(t *testing.T, c *Card) {
		assert.True(t, loginNeeded(c.tx), "Expected login needed")

		err := login(c.tx, DefaultPIN)
		require.NoError(t, err, "Failed to login")

		needed := loginNeeded(c.tx)
		require.False(t, needed, "Expected no login needed")
	})
}

func TestPINRetries(t *testing.T) {
	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		retries, err := c.Retries()
		require.NoError(t, err, "Failed to get retries")

		require.Less(t, retries, 15, "Invalid number of retries: %d", retries)
		require.LessOrEqual(t, 0, retries, "Invalid number of retries: %d", retries)
	})
}

func TestLogin(t *testing.T) {
	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		err := c.VerifyPIN(DefaultPIN)
		require.NoError(t, err, "Failed to login")
	})
}

func TestAuthenticate(t *testing.T) {
	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		err := c.authenticate(DefaultManagementKey)
		assert.NoError(t, err, "Failed to authenticate")
	})
}

func TestSetManagementKey(t *testing.T) {
	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		var mgmtKey ManagementKey
		_, err := io.ReadFull(c.Rand, mgmtKey[:])
		require.NoError(t, err, "Failed to generate management key")

		err = c.SetManagementKey(DefaultManagementKey, mgmtKey)
		require.NoError(t, err, "Failed to set management key")

		err = c.authenticate(mgmtKey)
		assert.NoError(t, err, "Failed to authenticate with new management key")

		err = c.SetManagementKey(mgmtKey, DefaultManagementKey)
		require.NoError(t, err, "Failed to reset management key")
	})
}

func TestUnblockPIN(t *testing.T) {
	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		badPIN := "0"
		for {
			err := login(c.tx, badPIN)
			require.Error(t, err, "Login with bad PIN succeeded")

			var e AuthError
			require.ErrorAs(t, err, &e, "Error returned was not a wrong PIN error")

			if e.Retries == 0 {
				break
			}
		}

		err := c.Unblock(DefaultPUK, DefaultPIN)
		require.NoError(t, err, "Failed to unblock PIN")

		err = login(c.tx, DefaultPIN)
		assert.NoError(t, err, "Failed to login with PIN after unblock")
	})
}

func TestChangePIN(t *testing.T) {
	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		newPIN := "654321"

		err := c.SetPIN(newPIN, newPIN)
		assert.Error(t, err, "Successfully changed PIN with invalid PIN, expected error")

		err = c.SetPIN(DefaultPIN, newPIN)
		require.NoError(t, err, "Failed to change PIN")

		err = c.SetPIN(newPIN, DefaultPIN)
		require.NoError(t, err, "Failed to reset PIN")
	})
}

func TestChangePUK(t *testing.T) {
	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		newPUK := "87654321"

		err := c.SetPUK(newPUK, newPUK)
		assert.Error(t, err, "Successfully changed puk with invalid puk, expected error")

		err = c.SetPUK(DefaultPUK, newPUK)
		require.NoError(t, err, "Failed to changing PUK")

		err = c.SetPUK(newPUK, DefaultPUK)
		require.NoError(t, err, "Failed to reset PUK")
	})
}

func TestChangeManagementKey(t *testing.T) {
	withCard(t, false, false, nil, func(t *testing.T, c *Card) {
		var newKey ManagementKey
		_, err := io.ReadFull(c.Rand, newKey[:])
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
	})
}
