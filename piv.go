// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

// Package piv implements management functionality for the YubiKey PIV applet.
package piv

import (
	"bytes"
	"crypto/des" //nolint:gosec
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ebfe/scard"
)

var (
	errChallengeFailed  = errors.New("challenge failed")
	errContextRelease   = errors.New("failed to release context")
	errExpectedError    = errors.New("expected error")
	errExpectedTag      = errors.New("expected tag")
	errInvalidHeader    = errors.New("invalid object header")
	errInvalidPinLength = errors.New("invalid pin length")
)

const (
	// DefaultPIN for the PIV applet. The PIN is used to change the Management Key,
	// and slots can optionally require it to perform signing operations.
	DefaultPIN = "123456"

	// DefaultPUK for the PIV applet. The PUK is only used to reset the PIN when
	// the card's PIN retries have been exhausted.
	DefaultPUK = "12345678"
)

// DefaultManagementKey for the PIV applet. The Management Key is a Triple-DES
// key required for slot actions such as generating keys, setting certificates,
// and signing.
//
//nolint:gochecknoglobals
var DefaultManagementKey = [24]byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
}

const (
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-78-4.pdf#page=17
	algTag     = 0x80
	alg3DES    = 0x03
	algRSA1024 = 0x06
	algRSA2048 = 0x07
	algECCP256 = 0x11
	algECCP384 = 0x14
	// non-standard; as implemented by SoloKeys. Chosen for low probability of eventual
	// clashes, if and when PIV standard adds Ed25519 support
	algEd25519 = 0x22

	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-78-4.pdf#page=16
	keyAuthentication     = 0x9a
	keyCardManagement     = 0x9b
	keySignature          = 0x9c
	keyKeyManagement      = 0x9d
	keyCardAuthentication = 0x9e
	keyAttestation        = 0xf9

	insVerify             = 0x20
	insChangeReference    = 0x24
	insResetRetry         = 0x2c
	insGenerateAsymmetric = 0x47
	insAuthenticate       = 0x87
	insGetData            = 0xcb
	insPutData            = 0xdb
	insSelectApplication  = 0xa4
	insGetResponseAPDU    = 0xc0

	// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0/lib/ykpiv.h#L656
	insSetMGMKey     = 0xff
	insImportKey     = 0xfe
	insGetVersion    = 0xfd
	insReset         = 0xfb
	insSetPINRetries = 0xfa
	insAttest        = 0xf9
	insGetSerial     = 0xf8
	insGetMetadata   = 0xf7
)

// YubiKey is an exclusive open connection to a YubiKey smart card. While open,
// no other process can query the given card.
//
// To release the connection, call the Close method.
type YubiKey struct {
	ctx *scard.Context
	h   *scard.Card
	tx  *scTx

	rand io.Reader

	// Used to determine how to access certain functionality.
	//
	// TODO: It's not clear what this actually communicates. Is this the
	// YubiKey's version or PIV version? A NEO reports v1.0.4. Figure this out
	// before exposing an API.
	version *version
}

// Close releases the connection to the smart card.
func (yk *YubiKey) Close() error {
	err1 := yk.h.Disconnect(scard.LeaveCard)
	err2 := yk.ctx.Release()
	if err1 == nil {
		return err2
	}
	return err1
}

// Open connects to a YubiKey smart card.
func Open(card string) (*YubiKey, error) {
	var c client
	return c.Open(card)
}

// Version returns the version as reported by the PIV applet. For newer
// YubiKeys (>=4.0.0) this corresponds to the version of the YubiKey itself.
//
// Older YubiKeys return values that aren't directly related to the YubiKey
// version. For example, 3rd generation YubiKeys report 1.0.X.
func (yk *YubiKey) Version() Version {
	return Version{
		Major: int(yk.version.major),
		Minor: int(yk.version.minor),
		Patch: int(yk.version.patch),
	}
}

// Serial returns the YubiKey's serial number.
func (yk *YubiKey) Serial() (uint32, error) {
	cmd := apdu{instruction: insGetSerial}
	if yk.version.major < 5 {
		// Earlier versions of YubiKeys required using the YubiKey applet to get
		// the serial number. Newer ones have this built into the PIV applet.
		if err := ykSelectApplication(yk.tx, aidYubiKey[:]); err != nil {
			return 0, fmt.Errorf("failed to select YubiKey applet: %w", err)
		}
		defer ykSelectApplication(yk.tx, aidPIV[:]) //nolint:errcheck
		cmd = apdu{instruction: 0x01, param1: 0x10}
	}
	resp, err := yk.tx.Transmit(cmd)
	if err != nil {
		return 0, fmt.Errorf("failed to execute command: %w", err)
	}
	if n := len(resp); n != 4 {
		return 0, fmt.Errorf("%w for serial number: got=%dB, want=4B", errUnexpectedLength, n)
	}
	return binary.BigEndian.Uint32(resp), nil
}

func encodePIN(pin string) ([]byte, error) {
	data := []byte(pin)
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: cannot be empty", errInvalidPinLength)
	}
	if len(data) > 8 {
		return nil, fmt.Errorf("%w: longer than 8 bytes", errInvalidPinLength)
	}
	// apply padding
	for i := len(data); i < 8; i++ {
		data = append(data, 0xff)
	}
	return data, nil
}

// VerifyPIN attempts to authenticate against the card with the provided PIN.
//
// PIN authentication for other operations are handled separately, and VerifyPIN
// does not need to be called before those methods.
//
// After a specific number of authentication attempts with an invalid PIN,
// usually 3, the PIN will become block and refuse further attempts. At that
// point the PUK must be used to unblock the PIN.
//
// Use DefaultPIN if the PIN hasn't been set.
func (yk *YubiKey) VerifyPIN(pin string) error {
	return ykLogin(yk.tx, pin)
}

func ykLogin(tx *scTx, pin string) error {
	data, err := encodePIN(pin)
	if err != nil {
		return err
	}

	// https://csrc.nist.gov/CSRC/media/Publications/sp/800-73/4/archive/2015-05-29/documents/sp800_73-4_pt2_draft.pdf#page=20
	cmd := apdu{instruction: insVerify, param2: 0x80, data: data}
	if _, err := tx.Transmit(cmd); err != nil {
		return fmt.Errorf("failed to verify pin: %w", err)
	}
	return nil
}

func ykLoginNeeded(tx *scTx) bool {
	cmd := apdu{instruction: insVerify, param2: 0x80}
	_, err := tx.Transmit(cmd)
	return err != nil
}

// Retries returns the number of attempts remaining to enter the correct PIN.
func (yk *YubiKey) Retries() (int, error) {
	cmd := apdu{instruction: insVerify, param2: 0x80}
	_, err := yk.tx.Transmit(cmd)
	if err == nil {
		return 0, fmt.Errorf("%w from empty pin", errExpectedError)
	}
	var e AuthError
	if errors.As(err, &e) {
		return e.Retries, nil
	}
	return 0, fmt.Errorf("invalid response: %w", err)
}

// Reset resets the YubiKey PIV applet to its factory settings, wiping all slots
// and resetting the PIN, PUK, and Management Key to their default values. This
// does NOT affect data on other applets, such as GPG or U2F.
func (yk *YubiKey) Reset() error {
	// Reset only works if both the PIN and PUK are blocked. Before resetting,
	// try the wrong PIN and PUK multiple times to block them.

	maxPIN := big.NewInt(100_000_000)
	pinInt, err := rand.Int(yk.rand, maxPIN)
	if err != nil {
		return fmt.Errorf("failed to generate random PIN: %w", err)
	}
	pukInt, err := rand.Int(yk.rand, maxPIN)
	if err != nil {
		return fmt.Errorf("failed to generate random PUK: %w", err)
	}

	pin := pinInt.String()
	puk := pukInt.String()

	for {
		err := ykLogin(yk.tx, pin)
		if err == nil {
			// TODO: do we care about a 1/100million chance?
			return fmt.Errorf("%w with random PIN", errExpectedError)
		}
		var e AuthError
		if !errors.As(err, &e) {
			return fmt.Errorf("blocking PIN: %w", err)
		}
		if e.Retries == 0 {
			break
		}
	}

	for {
		err := yk.SetPUK(puk, puk)
		if err == nil {
			// TODO: do we care about a 1/100million chance?
			return fmt.Errorf("%w with random PUK", errExpectedError)
		}
		var e AuthError
		if !errors.As(err, &e) {
			return fmt.Errorf("blocking PUK: %w", err)
		}
		if e.Retries == 0 {
			break
		}
	}

	cmd := apdu{instruction: insReset}
	if _, err := yk.tx.Transmit(cmd); err != nil {
		return fmt.Errorf("failed to reset YubiKey: %w", err)
	}
	return nil
}

type version struct {
	major byte
	minor byte
	patch byte
}

// authManagementKey attempts to authenticate against the card with the provided
// management key. The management key is required to generate new keys or add
// certificates to slots.
//
// Use DefaultManagementKey if the management key hasn't been set.
func (yk *YubiKey) authManagementKey(key [24]byte) error {
	return ykAuthenticate(yk.tx, key, yk.rand)
}

// Smartcard Application IDs for YubiKeys.
//
// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0/lib/ykpiv.c#L1877
// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0/lib/ykpiv.c#L108-L110
// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0/lib/ykpiv.c#L1117
//
//nolint:gochecknoglobals
var (
	aidManagement = [...]byte{0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17} //nolint:unused
	aidPIV        = [...]byte{0xa0, 0x00, 0x00, 0x03, 0x08}
	aidYubiKey    = [...]byte{0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01}
)

func ykAuthenticate(tx *scTx, key [24]byte, rand io.Reader) error {
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=92
	// https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=918402#page=114

	// request a witness
	cmd := apdu{
		instruction: insAuthenticate,
		param1:      alg3DES,
		param2:      keyCardManagement,
		data: []byte{
			0x7c, // Dynamic Authentication Template tag
			0x02, // Length of object
			0x80, // 'Witness'
			0x00, // Return encrypted random
		},
	}
	resp, err := tx.Transmit(cmd)
	if err != nil {
		return fmt.Errorf("failed to get auth challenge: %w", err)
	}
	if n := len(resp); n < 12 {
		return fmt.Errorf("%w: challenge didn't return enough bytes: got=%dB, want=12B", errUnexpectedLength, n)
	}
	if !bytes.Equal(resp[:4], []byte{
		0x7c,
		0x0a,
		0x80, // 'Witness'
		0x08, // Tag length
	}) {
		return fmt.Errorf("%w for authentication: %x", errInvalidHeader, resp[:4])
	}

	cardChallenge := resp[4 : 4+8]
	cardResponse := make([]byte, 8)

	block, err := des.NewTripleDESCipher(key[:]) //nolint:gosec
	if err != nil {
		return fmt.Errorf("failed to create triple des block cipher: %w", err)
	}
	block.Decrypt(cardResponse, cardChallenge)

	challenge := make([]byte, 8)
	if _, err := io.ReadFull(rand, challenge); err != nil {
		return fmt.Errorf("failed to read rand data: %w", err)
	}
	response := make([]byte, 8)
	block.Encrypt(response, challenge)

	data := []byte{
		0x7c, // Dynamic Authentication Template tag
		20,   // 2+8+2+8
		0x80, // 'Witness'
		0x08, // Tag length
	}
	data = append(data, cardResponse...)
	data = append(data,
		0x81, // 'Challenge'
		0x08, // Tag length
	)
	data = append(data, challenge...)

	cmd = apdu{
		instruction: insAuthenticate,
		param1:      alg3DES,
		param2:      keyCardManagement,
		data:        data,
	}
	resp, err = tx.Transmit(cmd)
	if err != nil {
		return fmt.Errorf("failed to authenticate challenge: %w", err)
	}
	if n := len(resp); n < 12 {
		return fmt.Errorf("%w: challenge response didn't return enough bytes: got=%dB, want=12B", errUnexpectedLength, n)
	}
	if !bytes.Equal(resp[:4], []byte{
		0x7c,
		0x0a,
		0x82, // 'Response'
		0x08,
	}) {
		return fmt.Errorf("%w for authentication: %x", errInvalidHeader, resp[:4])
	}
	if !bytes.Equal(resp[4:4+8], response) {
		return errChallengeFailed
	}

	return nil
}

// SetManagementKey updates the management key to a new key. Management keys
// are triple-des keys, however padding isn't verified. To generate a new key,
// generate 24 random bytes.
//
//	var newKey [24]byte
//	if _, err := io.ReadFull(rand.Reader, newKey[:]); err != nil {
//		// ...
//	}
//	if err := yk.SetManagementKey(piv.DefaultManagementKey, newKey); err != nil {
//		// ...
//	}
func (yk *YubiKey) SetManagementKey(oldKey, newKey [24]byte) error {
	if err := ykAuthenticate(yk.tx, oldKey, yk.rand); err != nil {
		return fmt.Errorf("failed to authenticate with old key: %w", err)
	}

	touch := false
	cmd := apdu{
		instruction: insSetMGMKey,
		param1:      0xff,
		param2:      0xff,
		data: append([]byte{
			alg3DES, keyCardManagement, 24,
		}, newKey[:]...),
	}
	if touch {
		cmd.param2 = 0xfe
	}
	if _, err := yk.tx.Transmit(cmd); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}
	return nil
}

// SetPIN updates the PIN to a new value. For compatibility, PINs should be 1-8
// numeric characters.
//
// To generate a new PIN, use the crypto/rand package.
//
//	// Generate a 6 character PIN.
//	newPINInt, err := rand.Int(rand.Reader, bit.NewInt(1_000_000))
//	if err != nil {
//		// ...
//	}
//	// Format with leading zeros.
//	newPIN := fmt.Sprintf("%06d", newPINInt)
//	if err := yk.SetPIN(piv.DefaultPIN, newPIN); err != nil {
//		// ...
//	}
func (yk *YubiKey) SetPIN(oldPIN, newPIN string) error {
	oldPINData, err := encodePIN(oldPIN)
	if err != nil {
		return fmt.Errorf("failed to encode old PIN: %w", err)
	}
	newPINData, err := encodePIN(newPIN)
	if err != nil {
		return fmt.Errorf("failed to encode new PIN: %w", err)
	}
	cmd := apdu{
		instruction: insChangeReference,
		param2:      0x80,
		data:        append(oldPINData, newPINData...),
	}
	_, err = yk.tx.Transmit(cmd)
	return err
}

// Unblock unblocks the PIN, setting it to a new value.
func (yk *YubiKey) Unblock(puk, newPIN string) error {
	pukData, err := encodePIN(puk)
	if err != nil {
		return fmt.Errorf("failed to encode PUK: %w", err)
	}
	newPINData, err := encodePIN(newPIN)
	if err != nil {
		return fmt.Errorf("failed to encode new PIN: %w", err)
	}
	cmd := apdu{
		instruction: insResetRetry,
		param2:      0x80,
		data:        append(pukData, newPINData...),
	}
	_, err = yk.tx.Transmit(cmd)
	return err
}

// SetPUK updates the PUK to a new value. For compatibility, PUKs should be 1-8
// numeric characters.
//
// To generate a new PUK, use the crypto/rand package.
//
//	// Generate a 8 character PUK.
//	newPUKInt, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
//	if err != nil {
//		// ...
//	}
//	// Format with leading zeros.
//	newPUK := fmt.Sprintf("%08d", newPUKInt)
//	if err := yk.SetPUK(piv.DefaultPUK, newPUK); err != nil {
//		// ...
//	}
func (yk *YubiKey) SetPUK(oldPUK, newPUK string) error {
	oldPUKData, err := encodePIN(oldPUK)
	if err != nil {
		return fmt.Errorf("failed to encode old PUK: %w", err)
	}
	newPUKData, err := encodePIN(newPUK)
	if err != nil {
		return fmt.Errorf("failed to encode new PUK: %w", err)
	}
	cmd := apdu{
		instruction: insChangeReference,
		param2:      0x81,
		data:        append(oldPUKData, newPUKData...),
	}
	_, err = yk.tx.Transmit(cmd)
	return err
}

func ykSelectApplication(tx *scTx, id []byte) error {
	cmd := apdu{
		instruction: insSelectApplication,
		param1:      0x04,
		data:        id,
	}
	if _, err := tx.Transmit(cmd); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}
	return nil
}

func ykVersion(tx *scTx) (*version, error) {
	cmd := apdu{
		instruction: insGetVersion,
	}
	resp, err := tx.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}
	if n := len(resp); n != 3 {
		return nil, fmt.Errorf("%w for version: got=%dB, want=3B", errUnexpectedLength, n)
	}
	return &version{resp[0], resp[1], resp[2]}, nil
}

func supportsVersion(v Version, major, minor, patch int) bool {
	if v.Major != major {
		return v.Major > major
	}
	if v.Minor != minor {
		return v.Minor > minor
	}
	return v.Patch >= patch
}
