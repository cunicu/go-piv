// SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package piv

// Appendix A––PIV Data Mode
//
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=37
//
//nolint:unused
const (
	// Table 8. Card Capability Container
	tagCardIdentifier             = 0xf0
	tagCapabilityContainerVersion = 0xf1
	tagCapabilityGrammarVersion   = 0xf2
	tagApplicationsCardURL        = 0xf3
	tagPKCS15                     = 0xf4
	tagRegisteredDataModel        = 0xf5
	tagAccessControlRuleTable     = 0xf6
	tagCardAPDUs                  = 0xf7
	tagRedirectionTag             = 0xfa
	tagCapabilityTuplesCTs        = 0xfb
	tagStatusTuplesSTs            = 0xfc
	tagNextCCC                    = 0xfd
	tagExtendedApplicationCardURL = 0xe3
	tagSecurityObjectBuffer       = 0xb4

	// Table 9. Card Holder Unique Identifier
	tagBufferLength              = 0xee
	tagFASCN                     = 0x30
	tagOrgID                     = 0x32
	tagDUNS                      = 0x33
	tagGUID                      = 0x34
	tagExpirationDate            = 0x35
	tagCardholderUUID            = 0x36
	tagIssuerAsymmetricSignature = 0x3e

	// Table 10. X.509 Certificate for PIV Authentication
	// Table 15. X.509 Certificate for Digital Signature
	// Table 16. X.509 Certificate for Key Management
	// Table 17. X.509 Certificate for Card Authentication
	// Tables 20-39. Retired X.509 Certificate for Key Management
	tagCertificate = 0x70
	tagCertInfo    = 0x71
	tagMSCUID      = 0x72

	// Table 11. Cardholder Fingerprints
	tagFingerprint = 0xbc

	// Table 12. Security Object
	tagMappingOfDGtoContainerID = 0xba
	tagSecurityObject           = 0xbb

	// Table 13. Cardholder Facial Image
	tagImageForVisualVerification = 0xbc

	// Table 14. Printed Information
	tagName                     = 0x01
	tagEmployeeAffiliation      = 0x02
	tagExpirationDatePrinted    = 0x04
	tagAgencyCardSerialNumber   = 0x05
	tagIssuerIdentification     = 0x06
	tagOrganizationAffiliation1 = 0x07
	tagOrganizationAffiliation2 = 0x08

	// Table 18. Discovery Object
	tagPIVCardApplicationAID = 0x4f
	tagPINUsagePolicy        = 0x5f2f

	// Table 19. Key History Object
	tagKeysWithOnCardCerts  = 0xc1
	tagKeysWithOffCardCerts = 0xc2
	tagOffCardCertURL       = 0xf3

	// Table 40. Cardholder Iris Images
	tagImagesForIris = 0xbc

	// Table 41. Biometric Information Templates Group Template
	tagNumberOfFingers    = 0x02
	tagBitForFirstFinger  = 0x7f60
	tagBitForSecondFinger = 0x7f60

	// Table 42. Secure Messaging Certificate Signer
	tagX509CertificateForContentSigning = 0x70
	tagIntermediateCVC                  = 0x7f21

	// Table 43. Pairing Code Reference Data Container
	tagPairingCode = 0x99

	// Common
	tagPINPolicy          = 0xaa
	tagTouchPolicy        = 0xab
	tagErrorDetectionCode = 0xfe
)
