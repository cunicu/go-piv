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
	for _, alg := range []Algorithm{Alg3DES, AlgAES128, AlgAES192, AlgAES256} {
		t.Run(alg.String(), func(t *testing.T) {
			withCard(t, false, false, nil, func(t *testing.T, c *Card) {
				var mgmtKey ManagementKey
				_, err := io.ReadFull(c.Rand, mgmtKey[:])
				require.NoError(t, err, "Failed to generate management key")

				err = c.SetManagementKey(DefaultManagementKey, mgmtKey, false, alg)
				require.NoError(t, err, "Failed to set management key")

				err = c.authenticate(mgmtKey)
				assert.NoError(t, err, "Failed to authenticate with new management key")

				err = c.SetManagementKey(mgmtKey, DefaultManagementKey, false, alg)
				require.NoError(t, err, "Failed to reset management key")
			})
		})
	}
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

		err = c.SetManagementKey(newKey, newKey, false, Alg3DES)
		assert.Error(t, err, "Successfully changed management key with invalid key, expected error")

		err = c.SetManagementKey(DefaultManagementKey, newKey, false, Alg3DES)
		require.NoError(t, err, "Failed to change management key")

		err = c.SetManagementKey(newKey, DefaultManagementKey, false, Alg3DES)
		require.NoError(t, err, "Failed to reset management key")
	})
}

func TestSetRetries(t *testing.T) {
	withCard(t, true, false, nil, func(t *testing.T, c *Card) {
		// Check default attempt counters
		for _, key := range []byte{keyPIN, keyPUK} {
			meta, err := c.Metadata(Slot{Key: key})
			require.NoError(t, err)
			require.Equal(t, 3, meta.RetriesRemaining)
			require.Equal(t, 3, meta.RetriesTotal)
			require.True(t, meta.IsDefault)
		}

		retries := map[byte]int{keyPIN: 5, keyPUK: 10}

		// Modify retry counter
		err := c.SetRetries(DefaultManagementKey, DefaultPIN, retries[keyPIN], retries[keyPUK])
		require.NoError(t, err)

		for key, cnt := range retries {
			meta, err := c.Metadata(Slot{Key: key})
			require.NoError(t, err)
			require.Equal(t, cnt, meta.RetriesRemaining)
			require.Equal(t, cnt, meta.RetriesTotal)
			require.True(t, meta.IsDefault)
		}

		// Update remaining retries
		var aErr AuthError

		err = c.VerifyPIN("92837492")
		require.ErrorAs(t, err, &aErr)
		require.Equal(t, retries[keyPIN]-1, aErr.Retries)

		err = c.Unblock("92837492", "12345678")
		require.ErrorAs(t, err, &aErr)
		require.Equal(t, retries[keyPUK]-1, aErr.Retries)

		for key, cnt := range retries {
			meta, err := c.Metadata(Slot{Key: key})
			require.NoError(t, err)
			require.Equal(t, cnt-1, meta.RetriesRemaining)
			require.Equal(t, cnt, meta.RetriesTotal)
			require.True(t, meta.IsDefault)
		}

		// Modify PIN/PUK
		err = c.SetPIN(DefaultPIN, "981211")
		require.NoError(t, err)

		err = c.SetPUK(DefaultPUK, "981211")
		require.NoError(t, err)

		for key, cnt := range retries {
			meta, err := c.Metadata(Slot{Key: key})
			require.NoError(t, err)
			require.Equal(t, cnt, meta.RetriesRemaining)
			require.Equal(t, cnt, meta.RetriesTotal)
			require.False(t, meta.IsDefault)
		}
	})
}
