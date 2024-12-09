// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto/x509"
	"fmt"

	"cunicu.li/go-iso7816/encoding/tlv"
)

// Certificate returns the certificate object stored in a given slot.
//
// If a certificate hasn't been set in the provided slot, the returned error
// wraps ErrNotFound.
func (c *Card) Certificate(slot Slot) (*x509.Certificate, error) {
	resp, err := sendTLV(c.tx, insGetData, 0x3f, 0xff, slot.Object.TagValue())
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}

	data, _, ok := resp.Get(0x53)
	if !ok {
		return nil, errUnmarshal
	}

	tvsCert, err := tlv.DecodeBER(data)
	if err != nil {
		return nil, errUnmarshal
	}

	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=85
	certDER, _, ok := tvsCert.Get(0x70)
	if !ok {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
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
func (c *Card) SetCertificate(key ManagementKey, slot Slot, cert *x509.Certificate) error {
	if err := c.authenticate(key); err != nil {
		return fmt.Errorf("failed to authenticate with management key: %w", err)
	}

	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=40
	certData, err := tlv.EncodeBER(
		tlv.New(tagCertificate, cert.Raw),
		tlv.New(tagCertInfo, 0x00), // "for a certificate encoded in uncompressed form CertInfo shall be 0x00"
		tlv.New(tagErrorDetectionCode),
	)
	if err != nil {
		return err
	}

	if _, err := sendTLV(c.tx, insPutData, 0x3f, 0xff,
		slot.Object.TagValue(),
		tlv.New(0x53, certData),
	); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	return nil
}
