// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

type algorithmType byte

const (
	AlgTypeRSA algorithmType = iota + 1
	AlgTypeECCP
	AlgTypeEd25519
)

// Algorithm represents a specific algorithm and bit size supported by the PIV
// specification.
type Algorithm byte

// Algorithms supported by this package. Note that not all cards will support
// every algorithm.
//
// AlgorithmEd25519 is currently only implemented by SoloKeys.
//
// For algorithm discovery, see: https://github.com/ericchiang/piv-go/issues/1
const (
	Alg3DES    Algorithm = 0x03
	AlgRSA1024 Algorithm = 0x06
	AlgRSA2048 Algorithm = 0x07
	AlgECCP256 Algorithm = 0x11
	AlgECCP384 Algorithm = 0x14

	// Non-standard; as implemented by SoloKeys. Chosen for low probability of eventual
	// clashes, if and when PIV standard adds Ed25519 support
	AlgEd25519 Algorithm = 0x22
)

func (a Algorithm) algType() algorithmType {
	switch a {
	case AlgRSA1024, AlgRSA2048:
		return AlgTypeRSA

	case AlgECCP256, AlgECCP384:
		return AlgTypeECCP

	case AlgEd25519:
		return AlgTypeEd25519

	default:
		return 0
	}
}

func (a Algorithm) bits() int {
	switch a {
	case AlgRSA1024:
		return 1024
	case AlgRSA2048:
		return 2048

	case AlgECCP256:
		return 256
	case AlgECCP384:
		return 384

	default:
		return 0
	}
}
