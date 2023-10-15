// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

// Package piv implements management functionality for the YubiKey PIV applet.
package piv

import (
	"bytes"
	"crypto/des" //nolint:gosec
	"crypto/rand"
	"encoding/asn1"
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

// Cards lists all smart cards available via PC/SC interface. Card names are
// strings describing the key, such as "Yubico Yubikey NEO OTP+U2F+CCID 00 00".
//
// Card names depend on the operating system and what port a card is plugged
// into. To uniquely identify a card, use its serial number.
//
// See: https://ludovicrousseau.blogspot.com/2010/05/what-is-in-pcsc-reader-name.html
func Cards() ([]string, error) {
	var c client
	return c.Cards()
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

// client is a smart card client and may be exported in the future to allow
// configuration for the top level Open() and Cards() APIs.
type client struct {
	// Rand is a cryptographic source of randomness used for card challenges.
	//
	// If nil, defaults to crypto.Rand.
	Rand io.Reader
}

func (c *client) Cards() ([]string, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PC/SC: %w", err)
	}

	readers, err := ctx.ListReaders()

	if err := ctx.Release(); err != nil {
		return nil, errContextRelease
	}

	if errors.Is(err, scard.ErrNoReadersAvailable) {
		return nil, nil
	}

	return readers, err
}

func (c *client) Open(card string) (*YubiKey, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to smart card daemon: %w", err)
	}

	h, err := ctx.Connect(card, scard.ShareExclusive, scard.ProtocolT1)
	if err != nil {
		if err := ctx.Release(); err != nil {
			return nil, fmt.Errorf("failed to release context: %w", err)
		}

		return nil, fmt.Errorf("failed to connect to smart card: %w", err)
	}
	tx, err := newTx(h)
	if err != nil {
		return nil, fmt.Errorf("failed to begin smart card transaction: %w", err)
	}
	if err := ykSelectApplication(tx, aidPIV[:]); err != nil {
		tx.Close()
		return nil, fmt.Errorf("failed to select PIV applet: %w", err)
	}

	yk := &YubiKey{ctx: ctx, h: h, tx: tx}
	v, err := ykVersion(yk.tx)
	if err != nil {
		yk.Close()
		return nil, fmt.Errorf("failed to get YubiKey version: %w", err)
	}
	yk.version = v
	if c.Rand != nil {
		yk.rand = c.Rand
	} else {
		yk.rand = rand.Reader
	}
	return yk, nil
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
	return ykSerial(yk.tx, yk.version)
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
	return ykPINRetries(yk.tx)
}

func ykPINRetries(tx *scTx) (int, error) {
	cmd := apdu{instruction: insVerify, param2: 0x80}
	_, err := tx.Transmit(cmd)
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
	return ykReset(yk.tx, yk.rand)
}

func ykReset(tx *scTx, r io.Reader) error {
	// Reset only works if both the PIN and PUK are blocked. Before resetting,
	// try the wrong PIN and PUK multiple times to block them.

	maxPIN := big.NewInt(100_000_000)
	pinInt, err := rand.Int(r, maxPIN)
	if err != nil {
		return fmt.Errorf("failed to generate random PIN: %w", err)
	}
	pukInt, err := rand.Int(r, maxPIN)
	if err != nil {
		return fmt.Errorf("failed to generate random PUK: %w", err)
	}

	pin := pinInt.String()
	puk := pukInt.String()

	for {
		err := ykLogin(tx, pin)
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
		err := ykChangePUK(tx, puk, puk)
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
	if _, err := tx.Transmit(cmd); err != nil {
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

	return ykSetManagementKey(yk.tx, newKey, false)
}

// ykSetManagementKey updates the management key to a new key. This requires
// authenticating with the existing management key.
func ykSetManagementKey(tx *scTx, key [24]byte, touch bool) error {
	cmd := apdu{
		instruction: insSetMGMKey,
		param1:      0xff,
		param2:      0xff,
		data: append([]byte{
			alg3DES, keyCardManagement, 24,
		}, key[:]...),
	}
	if touch {
		cmd.param2 = 0xfe
	}
	if _, err := tx.Transmit(cmd); err != nil {
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
	return ykChangePIN(yk.tx, oldPIN, newPIN)
}

func ykChangePIN(tx *scTx, oldPIN, newPIN string) error {
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
	_, err = tx.Transmit(cmd)
	return err
}

// Unblock unblocks the PIN, setting it to a new value.
func (yk *YubiKey) Unblock(puk, newPIN string) error {
	return ykUnblockPIN(yk.tx, puk, newPIN)
}

func ykUnblockPIN(tx *scTx, puk, newPIN string) error {
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
	_, err = tx.Transmit(cmd)
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
	return ykChangePUK(yk.tx, oldPUK, newPUK)
}

func ykChangePUK(tx *scTx, oldPUK, newPUK string) error {
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
	_, err = tx.Transmit(cmd)
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

func ykSerial(tx *scTx, v *version) (uint32, error) {
	cmd := apdu{instruction: insGetSerial}
	if v.major < 5 {
		// Earlier versions of YubiKeys required using the YubiKey applet to get
		// the serial number. Newer ones have this built into the PIV applet.
		if err := ykSelectApplication(tx, aidYubiKey[:]); err != nil {
			return 0, fmt.Errorf("failed to select YubiKey applet: %w", err)
		}
		defer ykSelectApplication(tx, aidPIV[:]) //nolint:errcheck
		cmd = apdu{instruction: 0x01, param1: 0x10}
	}
	resp, err := tx.Transmit(cmd)
	if err != nil {
		return 0, fmt.Errorf("failed to execute command: %w", err)
	}
	if n := len(resp); n != 4 {
		return 0, fmt.Errorf("%w for serial number: got=%dB, want=4B", errUnexpectedLength, n)
	}
	return binary.BigEndian.Uint32(resp), nil
}

// Metadata returns protected data stored on the card. This can be used to
// retrieve PIN protected management keys.
func (yk *YubiKey) Metadata(pin string) (*Metadata, error) {
	m, err := ykGetProtectedMetadata(yk.tx, pin)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return &Metadata{}, nil
		}
		return nil, err
	}
	return m, nil
}

// SetMetadata sets PIN protected metadata on the key. This is primarily to
// store the management key on the smart card instead of managing the PIN and
// management key separately.
func (yk *YubiKey) SetMetadata(key [24]byte, m *Metadata) error {
	return ykSetProtectedMetadata(yk.tx, key, m)
}

// Metadata holds protected metadata. This is primarily used by YubiKey manager
// to implement PIN protect management keys, storing management keys on the card
// guarded by the PIN.
type Metadata struct {
	// ManagementKey is the management key stored directly on the YubiKey.
	ManagementKey *[24]byte

	// raw, if not nil, is the full bytes
	raw []byte
}

func (m *Metadata) marshal() ([]byte, error) {
	if m.raw == nil {
		if m.ManagementKey == nil {
			return []byte{0x88, 0x00}, nil
		}
		return append([]byte{
			0x88,
			26,
			0x89,
			24,
		}, m.ManagementKey[:]...), nil
	}

	if m.ManagementKey == nil {
		return m.raw, nil
	}

	var metadata asn1.RawValue
	if _, err := asn1.Unmarshal(m.raw, &metadata); err != nil {
		return nil, fmt.Errorf("failed to update metadata: %w", err)
	}
	if !bytes.HasPrefix(metadata.FullBytes, []byte{0x88}) {
		return nil, fmt.Errorf("%w: 0x88", errExpectedTag)
	}
	raw := metadata.Bytes

	metadata.Bytes = nil
	metadata.FullBytes = nil

	for len(raw) > 0 {
		var (
			err error
			v   asn1.RawValue
		)
		raw, err = asn1.Unmarshal(raw, &v)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata field: %w", err)
		}

		if bytes.HasPrefix(v.FullBytes, []byte{0x89}) {
			continue
		}
		metadata.Bytes = append(metadata.Bytes, v.FullBytes...)
	}
	metadata.Bytes = append(metadata.Bytes, 0x89, 24)
	metadata.Bytes = append(metadata.Bytes, m.ManagementKey[:]...)
	return asn1.Marshal(metadata)
}

func (m *Metadata) unmarshal(b []byte) error {
	m.raw = b
	var md asn1.RawValue
	if _, err := asn1.Unmarshal(b, &md); err != nil {
		return err
	}
	if !bytes.HasPrefix(md.FullBytes, []byte{0x88}) {
		return fmt.Errorf("%w: 0x88", errExpectedTag)
	}
	d := md.Bytes
	for len(d) > 0 {
		var (
			err error
			v   asn1.RawValue
		)
		d, err = asn1.Unmarshal(d, &v)
		if err != nil {
			return fmt.Errorf("failed to unmarshal metadata field: %w", err)
		}
		if !bytes.HasPrefix(v.FullBytes, []byte{0x89}) {
			continue
		}
		// 0x89 indicates key
		if len(v.Bytes) != 24 {
			return fmt.Errorf("%w for management key: got=%dB, want=24B", errUnexpectedLength, len(v.Bytes))
		}
		var key [24]byte
		copy(key[:], v.Bytes)
		m.ManagementKey = &key
	}
	return nil
}

func ykGetProtectedMetadata(tx *scTx, pin string) (*Metadata, error) {
	// NOTE: for some reason this action requires the PIN to be authenticated on
	// the same transaction. It doesn't work otherwise.
	if err := ykLogin(tx, pin); err != nil {
		return nil, fmt.Errorf("failed to authenticate with PIN: %w", err)
	}
	cmd := apdu{
		instruction: insGetData,
		param1:      0x3f,
		param2:      0xff,
		data: []byte{
			0x5c, // Tag list
			0x03,
			0x5f,
			0xc1,
			0x09,
		},
	}
	resp, err := tx.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}
	obj, _, err := unmarshalASN1(resp, 1, 0x13) // tag 0x53
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	var m Metadata
	if err := m.unmarshal(obj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal protected metadata: %w", err)
	}
	return &m, nil
}

func ykSetProtectedMetadata(tx *scTx, key [24]byte, m *Metadata) error {
	data, err := m.marshal()
	if err != nil {
		return fmt.Errorf("failed to encode metadata: %w", err)
	}
	data = append([]byte{
		0x5c, // Tag list
		0x03,
		0x5f,
		0xc1,
		0x09,
	}, marshalASN1(0x53, data)...)
	cmd := apdu{
		instruction: insPutData,
		param1:      0x3f,
		param2:      0xff,
		data:        data,
	}
	// NOTE: for some reason this action requires the management key authenticated
	// on the same transaction. It doesn't work otherwise.
	if err := ykAuthenticate(tx, key, rand.Reader); err != nil {
		return fmt.Errorf("failed to authenticate with key: %w", err)
	}
	if _, err := tx.Transmit(cmd); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}
	return nil
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
