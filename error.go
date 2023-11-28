// SPDX-FileCopyrightText: 2020 Google LLC
// SPDX-License-Identifier: Apache-2.0

package piv

import (
	"errors"
	"fmt"

	iso "cunicu.li/go-iso7816"
)

func wrapCode(err error) error {
	c, ok := err.(iso.Code) //nolint:errorlint
	if !ok {
		return err
	}

	switch {
	case c == iso.ErrFileOrAppNotFound:
		return ErrNotFound

	case c == iso.ErrUnspecifiedWarningModified:
		return AuthError{0}

	case c == iso.ErrAuthenticationMethodBlocked:
		return AuthError{0}

	case c[0] == 0x63 && c[1]&0xf0 == 0xc0:
		return AuthError{int(c[1] & 0xf)}

	case c[0] == 0x63 && c[1]>>4 == 0x0:
		// Older YubiKeys sometimes return sw1=0x63 and sw2=0x0N to indicate the
		// number of retries. This isn't spec compliant, but support it anyway.
		//
		// https://cunicu.li/go-piv/issues/60
		return AuthError{int(c[1] & 0xf)}

	default:
		return err
	}
}

// AuthError is an error indicating an authentication error occurred (wrong PIN or blocked).
type AuthError struct {
	// Retries is the number of retries remaining if this error resulted from a retry-able
	// authentication attempt.  If the authentication method is blocked or does not support
	// retries, this will be 0.
	Retries int
}

func (v AuthError) Error() string {
	r := "retries"
	if v.Retries == 1 {
		r = "retry"
	}
	return fmt.Sprintf("verification failed (%d %s remaining)", v.Retries, r)
}

// ErrNotFound is returned when the requested object on the smart card is not found.
var ErrNotFound = errors.New("data object or application not found")
