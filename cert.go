// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto/x509"
	"fmt"
)

// Certificate returns the certificate object stored in a given slot.
//
// If a certificate hasn't been set in the provided slot, the returned error
// wraps ErrNotFound.
func (yk *YubiKey) Certificate(slot Slot) (*x509.Certificate, error) {
	cmd := apdu{
		instruction: insGetData,
		param1:      0x3f,
		param2:      0xff,
		data: []byte{
			0x5c, // Tag list
			0x03, // Length of tag
			byte(slot.Object >> 16),
			byte(slot.Object >> 8),
			byte(slot.Object),
		},
	}
	resp, err := yk.tx.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=85
	obj, _, err := unmarshalASN1(resp, 1, 0x13) // tag 0x53
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	certDER, _, err := unmarshalASN1(obj, 1, 0x10) // tag 0x70
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errParseCert, err)
	}
	return cert, nil
}

// SetCertificate stores a certificate object in the provided slot. Setting a
// certificate isn't required to use the associated key for signing or
// decryption.
func (yk *YubiKey) SetCertificate(key [24]byte, slot Slot, cert *x509.Certificate) error {
	if err := ykAuthenticate(yk.tx, key, yk.rand); err != nil {
		return fmt.Errorf("failed to authenticate with management key: %w", err)
	}
	return ykStoreCertificate(yk.tx, slot, cert)
}

func ykStoreCertificate(tx *scTx, slot Slot, cert *x509.Certificate) error {
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=40
	data := marshalASN1(0x70, cert.Raw)
	// "for a certificate encoded in uncompressed form CertInfo shall be 0x00"
	data = append(data, marshalASN1(0x71, []byte{0x00})...)
	// Error Detection Code
	data = append(data, marshalASN1(0xfe, nil)...)
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=94
	data = append([]byte{
		0x5c, // Tag list
		0x03, // Length of tag
		byte(slot.Object >> 16),
		byte(slot.Object >> 8),
		byte(slot.Object),
	}, marshalASN1(0x53, data)...)
	cmd := apdu{
		instruction: insPutData,
		param1:      0x3f,
		param2:      0xff,
		data:        data,
	}
	if _, err := tx.Transmit(cmd); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}
	return nil
}
