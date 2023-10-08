// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build darwin || linux || freebsd || openbsd
// +build darwin linux freebsd openbsd

package pcsc

// https://ludovicrousseau.blogspot.com/2010/04/pcsc-sample-in-c.html

// #cgo darwin LDFLAGS: -framework PCSC
// #cgo linux pkg-config: libpcsclite
// #cgo freebsd CFLAGS: -I/usr/local/include/
// #cgo freebsd CFLAGS: -I/usr/local/include/PCSC
// #cgo freebsd LDFLAGS: -L/usr/local/lib/
// #cgo freebsd LDFLAGS: -lpcsclite
// #cgo openbsd CFLAGS: -I/usr/local/include/
// #cgo openbsd CFLAGS: -I/usr/local/include/PCSC
// #cgo openbsd LDFLAGS: -L/usr/local/lib/
// #cgo openbsd LDFLAGS: -lpcsclite
// #include <PCSC/winscard.h>
// #include <PCSC/wintypes.h>
import "C"

import (
	"bytes"
	"fmt"
	"unsafe"
)

const rcSuccess = C.SCARD_S_SUCCESS

type Context struct {
	ctx C.SCARDCONTEXT
}

func NewContext() (*Context, error) {
	var ctx C.SCARDCONTEXT
	rc := C.SCardEstablishContext(C.SCARD_SCOPE_SYSTEM, nil, nil, &ctx)
	if err := scCheck(rc); err != nil {
		return nil, err
	}
	return &Context{ctx: ctx}, nil
}

func (c *Context) Release() error {
	return scCheck(C.SCardReleaseContext(c.ctx))
}

func (c *Context) ListReaders() ([]string, error) {
	var n C.DWORD
	rc := C.SCardListReaders(c.ctx, nil, nil, &n)
	// On Linux, the PC/SC daemon will return an error when no smart cards are
	// available. Detect this and return nil with no smart cards instead.
	//
	// isRCNoReaders is defined in OS specific packages.
	if isRCNoReaders(rc) {
		return nil, nil
	}

	if err := scCheck(rc); err != nil {
		return nil, err
	}

	d := make([]byte, n)
	rc = C.SCardListReaders(c.ctx, nil, (*C.char)(unsafe.Pointer(&d[0])), &n)
	if err := scCheck(rc); err != nil {
		return nil, err
	}

	var readers []string
	for _, d := range bytes.Split(d, []byte{0}) {
		if len(d) > 0 {
			readers = append(readers, string(d))
		}
	}
	return readers, nil
}

type Card struct {
	h C.SCARDHANDLE
}

func (c *Context) Connect(reader string) (*Card, error) {
	var (
		handle         C.SCARDHANDLE
		activeProtocol C.DWORD
	)
	rc := C.SCardConnect(c.ctx, C.CString(reader),
		C.SCARD_SHARE_EXCLUSIVE, C.SCARD_PROTOCOL_T1,
		&handle, &activeProtocol)
	if err := scCheck(rc); err != nil {
		return nil, err
	}
	return &Card{handle}, nil
}

func (h *Card) Close() error {
	return scCheck(C.SCardDisconnect(h.h, C.SCARD_LEAVE_CARD))
}

func (h *Card) BeginTransaction() error {
	return scCheck(C.SCardBeginTransaction(h.h))
}

func (h *Card) EndTransaction() error {
	return scCheck(C.SCardEndTransaction(h.h, C.SCARD_LEAVE_CARD))
}

func (h *Card) Transmit(req []byte) ([]byte, error) {
	var resp [C.MAX_BUFFER_SIZE_EXTENDED]byte
	reqN := C.DWORD(len(req))
	respN := C.DWORD(len(resp))
	rc := C.SCardTransmit(
		h.h,
		C.SCARD_PCI_T1,
		(*C.BYTE)(&req[0]), reqN, nil,
		(*C.BYTE)(&resp[0]), &respN)
	if err := scCheck(rc); err != nil {
		return nil, fmt.Errorf("transmitting request: %w", err)
	}
	return resp[:respN], nil
}
