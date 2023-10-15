// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

//nolint:gochecknoglobals
var (
	//nolint:unused
	originMap = map[Origin]byte{
		OriginGenerated: 0x01,
		OriginImported:  0x02,
	}

	originMapInv = map[byte]Origin{
		0x01: OriginGenerated,
		0x02: OriginImported,
	}
)

// Origin represents whether a key was generated on the hardware, or has been
// imported into it.
type Origin int

// Origins supported by this package.
const (
	OriginGenerated Origin = iota + 1
	OriginImported
)
