// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/devices/yubikey"
	"cunicu.li/go-iso7816/filter"
)

//nolint:gochecknoglobals
var (
	v430 = iso.Version{Major: 4, Minor: 3, Patch: 0}
	v530 = iso.Version{Major: 5, Minor: 3, Patch: 0}
	v571 = iso.Version{Major: 5, Minor: 7, Patch: 1}

	SupportsAttestation   = yubikey.HasVersion(v430)
	SupportsMetadata      = yubikey.HasVersion(v530)
	SupportsKeyMoveDelete = yubikey.HasVersion(v571)
)

func SupportsAlgorithm(alg Algorithm) filter.Filter {
	switch alg {
	case AlgRSA1024, AlgRSA2048, AlgECCP256, AlgECCP384:
		return yubikey.HasVersion(v430)

	case AlgRSA3072, AlgRSA4096, AlgX25519, AlgEd25519:
		return yubikey.HasVersion(v571)

	default:
		return filter.None
	}
}
