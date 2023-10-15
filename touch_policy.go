// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

//nolint:gochecknoglobals
var (
	touchPolicyMap = map[TouchPolicy]byte{
		TouchPolicyNever:  0x01,
		TouchPolicyAlways: 0x02,
		TouchPolicyCached: 0x03,
	}

	touchPolicyMapInv = map[byte]TouchPolicy{
		0x01: TouchPolicyNever,
		0x02: TouchPolicyAlways,
		0x03: TouchPolicyCached,
	}
)

// TouchPolicy represents proof-of-presence requirements when signing or
// decrypting with asymmetric key in a given slot.
type TouchPolicy int

// Touch policies supported by this package.
const (
	TouchPolicyNever TouchPolicy = iota + 1
	TouchPolicyAlways
	TouchPolicyCached
)
