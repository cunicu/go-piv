// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

//nolint:gochecknoglobals
var (
	algorithmsMap = map[Algorithm]byte{
		AlgorithmEC256:   algECS256,
		AlgorithmEC384:   algECCP384,
		AlgorithmEd25519: algEd25519,
		AlgorithmRSA1024: algRSA1024,
		AlgorithmRSA2048: algRSA2048,
	}

	algorithmsMapInv = map[byte]Algorithm{
		algECS256:  AlgorithmEC256,
		algECCP384: AlgorithmEC384,
		algEd25519: AlgorithmEd25519,
		algRSA1024: AlgorithmRSA1024,
		algRSA2048: AlgorithmRSA2048,
	}
)

// Algorithm represents a specific algorithm and bit size supported by the PIV
// specification.
type Algorithm int

// Algorithms supported by this package. Note that not all cards will support
// every algorithm.
//
// AlgorithmEd25519 is currently only implemented by SoloKeys.
//
// For algorithm discovery, see: https://github.com/ericchiang/piv-go/issues/1
const (
	AlgorithmEC256 Algorithm = iota + 1
	AlgorithmEC384
	AlgorithmEd25519
	AlgorithmRSA1024
	AlgorithmRSA2048
)
