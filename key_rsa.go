// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/encoding/tlv"

	rsafork "cunicu.li/go-piv/internal/rsa"
)

type keyRSA struct {
	c    *Card
	slot Slot
	pub  *rsa.PublicKey
	auth KeyAuth
	pp   PINPolicy
}

func (k *keyRSA) Public() crypto.PublicKey {
	return k.pub
}

func (k *keyRSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.auth.do(k.c, k.pp, func(tx *iso.Transaction) ([]byte, error) {
		return signRSA(tx, rand, k.slot, k.pub, digest, opts)
	})
}

func (k *keyRSA) Decrypt(_ io.Reader, msg []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	return k.auth.do(k.c, k.pp, func(tx *iso.Transaction) ([]byte, error) {
		return decryptRSA(tx, k.slot, k.pub, msg)
	})
}

func decodeRSAPublic(tvs tlv.TagValues) (*rsa.PublicKey, error) {
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	mod, _, ok := tvs.Get(0x81)
	if !ok {
		return nil, fmt.Errorf("%w modulus", errUnmarshal)
	}

	exp, _, ok := tvs.Get(0x82)
	if !ok {
		return nil, fmt.Errorf("%w exponent", errUnmarshal)
	}

	var n, e big.Int
	n.SetBytes(mod)
	e.SetBytes(exp)

	if !e.IsInt64() {
		return nil, fmt.Errorf("%w: returned exponent too large: %s", errUnexpectedLength, e.String())
	}

	return &rsa.PublicKey{N: &n, E: int(e.Int64())}, nil
}

func decryptRSA(tx *iso.Transaction, slot Slot, pub *rsa.PublicKey, data []byte) ([]byte, error) {
	alg, err := algRSA(pub)
	if err != nil {
		return nil, err
	}

	resp, err := sendTLV(tx, iso.InsGeneralAuthenticate, byte(alg), slot.Key,
		tlv.New(0x7c,
			tlv.New(0x82),
			tlv.New(0x81, data),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}

	decrypted, _, ok := resp.GetChild(0x7c, 0x82)
	if !ok {
		return nil, fmt.Errorf("%w response signature", errUnmarshal)
	}

	// Decrypted blob contains a bunch of random data. Look for a NULL byte which
	// indicates where the plain text starts.
	for i := 2; i+1 < len(decrypted); i++ {
		if decrypted[i] == 0x00 {
			return decrypted[i+1:], nil
		}
	}

	return nil, errInvalidPKCS1Padding
}

func signRSA(tx *iso.Transaction, rand io.Reader, slot Slot, pub *rsa.PublicKey, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	if hash.Size() != len(digest) {
		return nil, fmt.Errorf("%w: input must be a hashed message", errUnexpectedLength)
	}

	alg, err := algRSA(pub)
	if err != nil {
		return nil, err
	}

	var data []byte
	if o, ok := opts.(*rsa.PSSOptions); ok {
		salt, err := rsafork.NewSalt(rand, pub, hash, o)
		if err != nil {
			return nil, err
		}

		em, err := rsafork.EMSAPSSEncode(digest, pub, salt, hash.New())
		if err != nil {
			return nil, err
		}

		data = em
	} else {
		prefix, ok := hashPrefixes[hash]
		if !ok {
			return nil, fmt.Errorf("%w: crypto.Hash(%d)", errUnsupportedHashAlgorithm, hash)
		}

		// https://tools.ietf.org/pdf/rfc2313.pdf#page=9
		d := make([]byte, len(prefix)+len(digest))
		copy(d[:len(prefix)], prefix)
		copy(d[len(prefix):], digest)

		paddingLen := pub.Size() - 3 - len(d)
		if paddingLen < 0 {
			return nil, rsa.ErrMessageTooLong
		}

		padding := make([]byte, paddingLen)
		for i := range padding {
			padding[i] = 0xff
		}

		// https://tools.ietf.org/pdf/rfc2313.pdf#page=9
		data = append([]byte{0x00, 0x01}, padding...)
		data = append(data, 0x00)
		data = append(data, d...)
	}

	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=117
	resp, err := sendTLV(tx, iso.InsGeneralAuthenticate, byte(alg), slot.Key,
		tlv.New(0x7c,
			tlv.New(0x82),
			tlv.New(0x81, data),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}

	pkcs1v15Sig, _, ok := resp.GetChild(0x7c, 0x82) // 0x82
	if !ok {
		return nil, fmt.Errorf("%w response signature", errUnmarshal)
	}

	return pkcs1v15Sig, nil
}

func algRSA(pub *rsa.PublicKey) (Algorithm, error) {
	size := pub.N.BitLen()
	switch size {
	case 1024:
		return AlgRSA1024, nil

	case 2048:
		return AlgRSA2048, nil

	default:
		return 0, fmt.Errorf("%w: %d", errUnsupportedKeySize, size)
	}
}

// PKCS#1 v15 is largely informed by the standard library
// https://github.com/golang/go/blob/go1.13.5/src/crypto/rsa/pkcs1v15.go

//nolint:gochecknoglobals
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}
