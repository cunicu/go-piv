// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"encoding/asn1"
	"fmt"
)

// marshalASN1Length encodes the length.
func marshalASN1Length(n uint64) []byte {
	var l []byte
	switch {
	case n < 0x80:
		l = []byte{byte(n)}
	case n < 0x100:
		l = []byte{0x81, byte(n)}
	default:
		l = []byte{0x82, byte(n >> 8), byte(n)}
	}

	return l
}

// marshalASN1 encodes a tag, length and data.
//
// TODO: clean this up and maybe switch to cryptobyte?
func marshalASN1(tag byte, data []byte) []byte {
	l := marshalASN1Length(uint64(len(data)))
	d := append([]byte{tag}, l...)
	return append(d, data...)
}

func unmarshalASN1(b []byte, class, tag int) (obj, rest []byte, err error) {
	var v asn1.RawValue
	if rest, err = asn1.Unmarshal(b, &v); err != nil {
		return nil, nil, err
	}
	if v.Class != class || v.Tag != tag {
		return nil, nil, fmt.Errorf("%w: got=%d/%x, want=%d/%x", errUnexpectedClassTag, v.Class, v.Tag, class, tag)
	}
	return v.Bytes, rest, nil
}
