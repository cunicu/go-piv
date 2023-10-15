// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Prefix in the x509 Subject Common Name for YubiKey attestations
// https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
const yubikeySubjectCNPrefix = "YubiKey PIV Attestation "

// Attestation returns additional information about a key attested to be generated
// on a card. See https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
// for more information.
type Attestation struct {
	// Version of the YubiKey's firmware.
	Version Version
	// Serial is the YubiKey's serial number.
	Serial uint32
	// Formfactor indicates the physical type of the YubiKey.
	//
	// Formfactor may be empty Formfactor(0) for some YubiKeys.
	Formfactor Formfactor

	// PINPolicy set on the slot.
	PINPolicy PINPolicy
	// TouchPolicy set on the slot.
	TouchPolicy TouchPolicy

	// Slot is the inferred slot the attested key resides in based on the
	// common name in the attestation. If the slot cannot be determined,
	// this field will be an empty struct.
	Slot Slot
}

func (a *Attestation) addExt(e pkix.Extension) error {
	switch {
	case e.Id.Equal(extIDFirmwareVersion):
		if len(e.Value) != 3 {
			return fmt.Errorf("%w for firmware version, got=%dB, want=3B", errUnexpectedLength, len(e.Value))
		}
		a.Version = Version{
			Major: int(e.Value[0]),
			Minor: int(e.Value[1]),
			Patch: int(e.Value[2]),
		}
	case e.Id.Equal(extIDSerialNumber):
		var serial int64
		if _, err := asn1.Unmarshal(e.Value, &serial); err != nil {
			return fmt.Errorf("failed to parse serial number: %w", err)
		}
		if serial < 0 {
			return fmt.Errorf("%w: is negative %d", errInvalidSerialNumber, serial)
		}
		a.Serial = uint32(serial)
	case e.Id.Equal(extIDKeyPolicy):
		if len(e.Value) != 2 {
			return fmt.Errorf("%w for key policy: got=%dB, want=2B", errUnexpectedLength, len(e.Value))
		}
		switch e.Value[0] {
		case 0x01:
			a.PINPolicy = PINPolicyNever
		case 0x02:
			a.PINPolicy = PINPolicyOnce
		case 0x03:
			a.PINPolicy = PINPolicyAlways
		default:
			return fmt.Errorf("%w: 0x%x", errUnsupportedPinPolicy, e.Value[0])
		}
		switch e.Value[1] {
		case 0x01:
			a.TouchPolicy = TouchPolicyNever
		case 0x02:
			a.TouchPolicy = TouchPolicyAlways
		case 0x03:
			a.TouchPolicy = TouchPolicyCached
		default:
			return fmt.Errorf("%w: 0x%x", errUnsupportedTouchPolicy, e.Value[1])
		}
	case e.Id.Equal(extIDFormFactor):
		if len(e.Value) != 1 {
			return fmt.Errorf("%w: expected 1 byte for form factor, got=%d", errUnexpectedLength, len(e.Value))
		}
		a.Formfactor = Formfactor(e.Value[0])
	}
	return nil
}

// Verify proves that a key was generated on a YubiKey. It ensures the slot and
// YubiKey certificate chains up to the Yubico CA, parsing additional information
// out of the slot certificate, such as the touch and PIN policies of a key.
func Verify(attestationCert, slotCert *x509.Certificate) (*Attestation, error) {
	var v Verifier
	return v.Verify(attestationCert, slotCert)
}

// Verifier allows specifying options when verifying attestations produced by
// YubiKeys.
type Verifier struct {
	// Root certificates to use to validate challenges. If nil, this defaults to Yubico's
	// CA bundle.
	//
	// https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
	// https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem
	// https://developers.yubico.com/U2F/yubico-u2f-ca-certs.txt
	Roots *x509.CertPool
}

// Verify proves that a key was generated on a YubiKey.
//
// As opposed to the package level [Verify], it uses any options enabled on the [Verifier].
func (v *Verifier) Verify(attestationCert, slotCert *x509.Certificate) (*Attestation, error) {
	o := x509.VerifyOptions{KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	o.Roots = v.Roots
	if o.Roots == nil {
		cas, err := yubicoCAs()
		if err != nil {
			return nil, fmt.Errorf("failed to load yubico CAs: %w", err)
		}
		o.Roots = cas
	}

	o.Intermediates = x509.NewCertPool()

	// The attestation cert in some yubikey 4 does not encode X509v3 Basic Constraints.
	// This isn't valid as per https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
	// (fourth paragraph) and thus makes x509.go validation fail.
	// Work around this by setting this constraint here.
	if !attestationCert.BasicConstraintsValid {
		attestationCert.BasicConstraintsValid = true
		attestationCert.IsCA = true
	}

	o.Intermediates.AddCert(attestationCert)

	if _, err := slotCert.Verify(o); err != nil {
		return nil, fmt.Errorf("failed to verify attestation certificate: %w", err)
	}
	return parseAttestation(slotCert)
}

func parseAttestation(slotCert *x509.Certificate) (*Attestation, error) {
	var a Attestation
	for _, ext := range slotCert.Extensions {
		if err := a.addExt(ext); err != nil {
			return nil, fmt.Errorf("failed to parse extension: %w", err)
		}
	}

	slot, ok := parseSlot(slotCert.Subject.CommonName)
	if ok {
		a.Slot = slot
	}

	return &a, nil
}

// AttestationCertificate returns the YubiKey's attestation certificate, which
// is unique to the key and signed by Yubico.
func (yk *YubiKey) AttestationCertificate() (*x509.Certificate, error) {
	return yk.Certificate(slotAttestation)
}

// Attest generates a certificate for a key, signed by the YubiKey's attestation
// certificate. This can be used to prove a key was generate on a specific
// YubiKey.
//
// This method is only supported for YubiKey versions >= 4.3.0.
// https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
//
// Certificates returned by this method MUST NOT be used for anything other than
// attestation or determining the slots public key. For example, the certificate
// is NOT suitable for TLS.
//
// If the slot doesn't have a key, the returned error wraps ErrNotFound.
func (yk *YubiKey) Attest(slot Slot) (cert *x509.Certificate, err error) {
	if cert, err = ykAttest(yk.tx, slot); err == nil {
		return cert, nil
	}
	var e *apduError
	if errors.As(err, &e) && e.sw1 == 0x6A && e.sw2 == 0x80 {
		return nil, ErrNotFound
	}
	return nil, err
}

func ykAttest(tx *scTx, slot Slot) (*x509.Certificate, error) {
	cmd := apdu{
		instruction: insAttest,
		param1:      byte(slot.Key),
	}
	resp, err := tx.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}
	if bytes.HasPrefix(resp, []byte{0x70}) {
		b, _, err := unmarshalASN1(resp, 0, 0x10)
		if err != nil { // tag 0x70
			return nil, fmt.Errorf("failed to unmarshal certificate: %w", err)
		}
		resp = b
	}
	cert, err := x509.ParseCertificate(resp)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errParseCert, err)
	}
	return cert, nil
}
