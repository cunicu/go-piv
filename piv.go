// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

// Package piv implements management functionality for the YubiKey PIV applet.
package piv

//nolint:gosec
import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/devices/yubikey"
	"cunicu.li/go-iso7816/encoding/tlv"
)

var (
	errChallengeFailed  = errors.New("challenge failed")
	errExpectedError    = errors.New("expected error")
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

var errInvalidManagementKeyLength = errors.New("invalid management key length")

type ManagementKey [24]byte

// DefaultManagementKey for the PIV applet. The Management Key is a Triple-DES
// key required for slot actions such as generating keys, setting certificates,
// and signing.
//
//nolint:gochecknoglobals
var DefaultManagementKey = ManagementKey{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
}

const (
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-78-4.pdf#page=17
	tagAlg = 0x80

	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-78-4.pdf#page=16
	keyAuthentication     = 0x9a
	keyCardManagement     = 0x9b
	keySignature          = 0x9c
	keyKeyManagement      = 0x9d
	keyCardAuthentication = 0x9e
	keyAttestation        = 0xf9

	// TODO: Figure out why these are different from iso7816 ins.
	insGenerateAsymmetric = 0x47
	insGetData            = 0xcb
	insPutData            = 0xdb

	// Yubico PIV extensions
	//
	// See:
	// - https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
	// - https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0/lib/ykpiv.h#L656
	insSetManagementKey = 0xff
	insImportKey        = 0xfe
	insGetVersion       = 0xfd
	insReset            = 0xfb
	insSetPINRetries    = 0xfa
	insAttest           = 0xf9
	insGetSerial        = 0xf8
	insGetMetadata      = 0xf7
)

// Card is an exclusive open connection to a Card smart card. While open,
// no other process can query the given card.
//
// To release the connection, call the Close method.
type Card struct {
	*iso.Card

	Rand io.Reader

	// Used to determine how to access certain functionality.
	//
	// TODO: It's not clear what this actually communicates. Is this the
	// YubiKey's version or PIV version? A NEO reports v1.0.4. Figure this out
	// before exposing an API.
	version *iso.Version

	tx *iso.Transaction
}

func NewCard(card *iso.Card) (pivCard *Card, err error) {
	pivCard = &Card{
		Card: card,
		Rand: rand.Reader,
	}

	if pivCard.tx, err = card.NewTransaction(); err != nil {
		return nil, fmt.Errorf("failed to begin smart card transaction: %w", err)
	}

	if _, err := pivCard.tx.Select(iso.AidPIV); err != nil {
		pivCard.tx.Close()
		return nil, fmt.Errorf("failed to select PIV applet: %w", err)
	}

	if pivCard.version, err = pivCard.getVersion(); err != nil {
		pivCard.Close()
		return nil, fmt.Errorf("failed to get YubiKey version: %w", err)
	}

	return pivCard, nil
}

// Close releases the connection to the smart card.
func (c *Card) Close() error {
	if c.tx != nil {
		if err := c.tx.Close(); err != nil {
			return err
		}
	}

	return nil
}

// Version returns the version as reported by the PIV applet. For newer
// YubiKeys (>=4.0.0) this corresponds to the version of the YubiKey itself.
//
// Older YubiKeys return values that aren't directly related to the YubiKey
// version. For example, 3rd generation YubiKeys report 1.0.X.
func (c *Card) Version() iso.Version {
	return *c.version
}

// Serial returns the YubiKey's serial number.
func (c *Card) Serial() (uint32, error) {
	if c.version.Major < 5 {
		// Earlier versions of YubiKeys required using the YubiKey applet to get
		// the serial number. Newer ones have this built into the PIV applet.
		if _, err := c.Select(iso.AidYubicoOTP); err != nil {
			return 0, fmt.Errorf("failed to select YubiKey applet: %w", err)
		}

		defer c.Select(iso.AidPIV) //nolint:errcheck

		return yubikey.GetSerialNumber(c.Card)
	}

	resp, err := send(c.tx, insGetSerial, 0, 0, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to execute command: %w", err)
	}

	if n := len(resp); n != 4 {
		return 0, fmt.Errorf("%w for serial number: got=%dB, want=4B", errUnexpectedLength, n)
	}

	return binary.BigEndian.Uint32(resp), nil
}

// Reset resets the PIV applet to its factory settings, wiping all slots
// and resetting the PIN, PUK, and Management Key to their default values. This
// does NOT affect data on other applets, such as GPG or U2F.
func (c *Card) Reset() error {
	// Reset only works if both the PIN and PUK are blocked. Before resetting,
	// try the wrong PIN and PUK multiple times to block them.

	maxPIN := big.NewInt(100_000_000)
	pinInt, err := rand.Int(c.Rand, maxPIN)
	if err != nil {
		return fmt.Errorf("failed to generate random PIN: %w", err)
	}

	pukInt, err := rand.Int(c.Rand, maxPIN)
	if err != nil {
		return fmt.Errorf("failed to generate random PUK: %w", err)
	}

	pin := pinInt.String()
	puk := pukInt.String()

	for {
		err = login(c.tx, pin)
		if err == nil {
			// TODO: do we care about a 1/100million chance?
			return fmt.Errorf("%w with random PIN", errExpectedError)
		}

		var e AuthError
		if !errors.As(err, &e) {
			return fmt.Errorf("failed to block PIN: %w", err)
		}

		if e.Retries == 0 {
			break
		}
	}

	for {
		err := c.SetPUK(puk, puk)
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

	if _, err = send(c.tx, insReset, 0, 0, nil); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	return nil
}

func (c *Card) getVersion() (*iso.Version, error) {
	resp, err := send(c.tx, insGetVersion, 0, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}

	if n := len(resp); n != 3 {
		return nil, fmt.Errorf("%w for version: got=%dB, want=3B", errUnexpectedLength, n)
	}

	return &iso.Version{
		Major: int(resp[0]),
		Minor: int(resp[1]),
		Patch: int(resp[2]),
	}, nil
}

func send(tx *iso.Transaction, ins iso.Instruction, p1, p2 byte, data []byte) ([]byte, error) {
	resp, err := tx.Send(&iso.CAPDU{
		Ins:  ins,
		P1:   p1,
		P2:   p2,
		Data: data,
	})
	if err != nil {
		return nil, wrapCode(err)
	}

	return resp, nil
}

func sendTLV(tx *iso.Transaction, ins iso.Instruction, p1, p2 byte, vs ...tlv.TagValue) (tlv.TagValues, error) {
	data, err := tlv.EncodeBER(vs...)
	if err != nil {
		return nil, fmt.Errorf("failed to encode data: %w", err)
	}

	resp, err := send(tx, ins, p1, p2, data)
	if err != nil {
		return nil, err
	}

	tvs, err := tlv.DecodeBER(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return tvs, nil
}
