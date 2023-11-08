// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package piv

import "cunicu.li/go-iso7816/encoding/tlv"

type Object []byte

//nolint:unused,gochecknoglobals
var (
	doDiscovery              = Object{0x7E}             //	PIV AID plus PIN usage policy
	doCertAuthentication     = Object{0x5F, 0xC1, 0x05} // Cert for key in slot 9A
	doCertSignature          = Object{0x5F, 0xC1, 0x0A} // Cert for key in slot 9C
	doCertKeyManagement      = Object{0x5F, 0xC1, 0x0B} // Cert for key in slot 9D
	doCertCardAuthentication = Object{0x5F, 0xC1, 0x01} // Cert for key in slot 9E
	doCertRetired1           = Object{0x5F, 0xC1, 0x0D} // Retired certs
	doCHUID                  = Object{0x5F, 0xC1, 0x02} // Cardholder Unique Identifier
	doCapability             = Object{0x5F, 0xC1, 0x07} // Card Capability Container (CCC)
	doPrinted                = Object{0x5F, 0xC1, 0x09} // Information printed on the card
	doSecurity               = Object{0x5F, 0xC1, 0x06} // Security object
	doKeyHistory             = Object{0x5F, 0xC1, 0x0C} // Info about retired keys
	doIRIS                   = Object{0x5F, 0xC1, 0x21} // Cardholder iris images
	doFacialImage            = Object{0x5F, 0xC1, 0x08} // Cardholder facial image
	doFingerprints           = Object{0x5F, 0xC1, 0x03} // Cardholder fingerprints
	doBITGT                  = Object{0x7F, 0x61}       // Biometric Information Group Template
	doSmSigner               = Object{0x5F, 0xC1, 0x22} // Secure Messaging Certificate Signer
	doPCRefData              = Object{0x5F, 0xC1, 0x23} // Pairing Code Reference Data

	// YubiKey specific
	doAdmin           = Object{0x5F, 0xFF, 0x00} // Admin Data
	doCertAttestation = Object{0x5F, 0xFF, 0x01} // Attestation Cert
	doMSCMAP          = Object{0x5F, 0xFF, 0x10} //	MSCMAP
	doMSROOTS1        = Object{0x5F, 0xFF, 0x11} // MSROOTS
)

func (o Object) TagValue() tlv.TagValue {
	return tlv.New(0x5c, []byte(o))
}
