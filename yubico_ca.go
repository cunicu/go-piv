// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	_ "embed"
)

// yubicoPIVCAPEMAfter2018 is the PEM encoded attestation certificate used by Yubico.
//
// https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
//
//go:embed certs/yubico_piv_attestation.crt
var yubicoPIVCAPEMAfter2018 string

// YubiKeys manufactured sometime in 2018 and prior to mid-2017
// were certified using the U2F root CA with serial number 457200631
// See https://github.com/Yubico/developers.yubico.com/pull/392/commits/a58f1003f003e04fc9baf09cad9f64f0c284fd47
// Cert available at https://developers.yubico.com/U2F/yubico-u2f-ca-certs.txt
//
//go:embed certs/yubico_u2f.crt
var yubicoPIVCAPEMU2F string

func yubicoCAs() (*x509.CertPool, error) {
	certPool := x509.NewCertPool()

	if !certPool.AppendCertsFromPEM([]byte(yubicoPIVCAPEMAfter2018)) {
		return nil, errParseCert
	}

	bU2F, _ := pem.Decode([]byte(yubicoPIVCAPEMU2F))
	if bU2F == nil {
		return nil, errParseCert
	}

	certU2F, err := x509.ParseCertificate(bU2F.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errParseCert, err)
	}

	// The U2F root cert has pathlen x509 basic constraint set to 0.
	// As per RFC 5280 this means that no intermediate cert is allowed
	// in the validation path. This isn't really helpful since we do
	// want to use the device attestation cert as intermediate cert in
	// the chain. To make this work, set pathlen of the U2F root to 1.
	//
	// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
	certU2F.MaxPathLen = 1
	certPool.AddCert(certU2F)

	return certPool, nil
}
