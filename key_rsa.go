// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"

	rsafork "cunicu.li/go-piv/internal/rsa"
)

type keyRSA struct {
	yk   *YubiKey
	slot Slot
	pub  *rsa.PublicKey
	auth KeyAuth
	pp   PINPolicy
}

func (k *keyRSA) Public() crypto.PublicKey {
	return k.pub
}

func (k *keyRSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.auth.do(k.yk, k.pp, func(tx *scTx) ([]byte, error) {
		return ykSignRSA(tx, rand, k.slot, k.pub, digest, opts)
	})
}

func (k *keyRSA) Decrypt(_ io.Reader, msg []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	return k.auth.do(k.yk, k.pp, func(tx *scTx) ([]byte, error) {
		return ykDecryptRSA(tx, k.slot, k.pub, msg)
	})
}

func decodeRSAPublic(b []byte) (*rsa.PublicKey, error) {
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	mod, r, err := unmarshalASN1(b, 2, 0x01)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal modulus: %w", err)
	}
	exp, _, err := unmarshalASN1(r, 2, 0x02)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal exponent: %w", err)
	}
	var n, e big.Int
	n.SetBytes(mod)
	e.SetBytes(exp)
	if !e.IsInt64() {
		return nil, fmt.Errorf("%w: returned exponent too large: %s", errUnexpectedLength, e.String())
	}
	return &rsa.PublicKey{N: &n, E: int(e.Int64())}, nil
}

func ykDecryptRSA(tx *scTx, slot Slot, pub *rsa.PublicKey, data []byte) ([]byte, error) {
	alg, err := rsaAlg(pub)
	if err != nil {
		return nil, err
	}
	cmd := apdu{
		instruction: insAuthenticate,
		param1:      alg,
		param2:      byte(slot.Key),
		data: marshalASN1(0x7c,
			append([]byte{0x82, 0x00},
				marshalASN1(0x81, data)...)),
	}
	resp, err := tx.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}

	sig, _, err := unmarshalASN1(resp, 1, 0x1c) // 0x7c
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	decrypted, _, err := unmarshalASN1(sig, 2, 0x02) // 0x82
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response signature: %w", err)
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

func ykSignRSA(tx *scTx, rand io.Reader, slot Slot, pub *rsa.PublicKey, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	if hash.Size() != len(digest) {
		return nil, fmt.Errorf("%w: input must be a hashed message", errUnexpectedLength)
	}

	alg, err := rsaAlg(pub)
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
	cmd := apdu{
		instruction: insAuthenticate,
		param1:      alg,
		param2:      byte(slot.Key),
		data: marshalASN1(0x7c,
			append([]byte{0x82, 0x00},
				marshalASN1(0x81, data)...)),
	}
	resp, err := tx.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}

	sig, _, err := unmarshalASN1(resp, 1, 0x1c) // 0x7c
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	pkcs1v15Sig, _, err := unmarshalASN1(sig, 2, 0x02) // 0x82
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response signature: %w", err)
	}
	return pkcs1v15Sig, nil
}

func rsaAlg(pub *rsa.PublicKey) (byte, error) {
	size := pub.N.BitLen()
	switch size {
	case 1024:
		return algRSA1024, nil
	case 2048:
		return algRSA2048, nil
	default:
		return 0, fmt.Errorf("%w: %d", errUnsupportedKeySize, size)
	}
}
