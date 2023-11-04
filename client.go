// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/ebfe/scard"
)

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

func (c *client) Open(cardName string) (*Card, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to smart card daemon: %w", err)
	}

	h, err := ctx.Connect(cardName, scard.ShareExclusive, scard.ProtocolT1)
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
	if err := selectApplication(tx, aidPIV[:]); err != nil {
		tx.Close()
		return nil, fmt.Errorf("failed to select PIV applet: %w", err)
	}

	card := &Card{ctx: ctx, h: h, tx: tx}
	v, err := getVersion(card.tx)
	if err != nil {
		card.Close()
		return nil, fmt.Errorf("failed to get YubiKey version: %w", err)
	}
	card.version = v
	if c.Rand != nil {
		card.rand = c.Rand
	} else {
		card.rand = rand.Reader
	}
	return card, nil
}
