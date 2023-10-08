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

package pcsc

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	winscard                  = syscall.NewLazyDLL("Winscard.dll")
	procSCardEstablishContext = winscard.NewProc("SCardEstablishContext")
	procSCardListReadersW     = winscard.NewProc("SCardListReadersW")
	procSCardReleaseContext   = winscard.NewProc("SCardReleaseContext")
	procSCardConnectW         = winscard.NewProc("SCardConnectW")
	procSCardDisconnect       = winscard.NewProc("SCardDisconnect")
	procSCardBeginTransaction = winscard.NewProc("SCardBeginTransaction")
	procSCardEndTransaction   = winscard.NewProc("SCardEndTransaction")
	procSCardTransmit         = winscard.NewProc("SCardTransmit")
)

const (
	scardScopeSystem      = 2
	scardShareExclusive   = 1
	scardLeaveCard        = 0
	scardProtocolT1       = 2
	scardPCIT1            = 0
	maxBufferSizeExtended = (4 + 3 + (1 << 16) + 3 + 2)
	rcSuccess             = 0
)

func scCheck(rc uintptr) error {
	if rc == rcSuccess {
		return nil
	}
	return &scErr{int64(rc)}
}

func isRCNoReaders(rc uintptr) bool {
	return rc == 0x8010002E
}

type Context struct {
	ctx syscall.Handle
}

func NewContext() (*Context, error) {
	var ctx syscall.Handle

	r0, _, _ := procSCardEstablishContext.Call(
		uintptr(scardScopeSystem),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if err := scCheck(r0); err != nil {
		return nil, err
	}
	return &Context{ctx: ctx}, nil
}

func (c *Context) Release() error {
	r0, _, _ := procSCardReleaseContext.Call(uintptr(c.ctx))
	return scCheck(r0)
}

func (c *Context) ListReaders() ([]string, error) {
	var n uint32
	r0, _, _ := procSCardListReadersW.Call(
		uintptr(c.ctx),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(&n)),
	)

	if isRCNoReaders(r0) {
		return nil, nil
	}

	if err := scCheck(r0); err != nil {
		return nil, err
	}

	d := make([]uint16, n)
	r0, _, _ = procSCardListReadersW.Call(
		uintptr(c.ctx),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(&d[0])),
		uintptr(unsafe.Pointer(&n)),
	)
	if err := scCheck(r0); err != nil {
		return nil, err
	}

	var readers []string
	j := 0
	for i := 0; i < len(d); i++ {
		if d[i] != 0 {
			continue
		}
		readers = append(readers, syscall.UTF16ToString(d[j:i]))
		j = i + 1

		if d[i+1] == 0 {
			break
		}
	}

	return readers, nil
}

func (c *Context) Connect(reader string) (*Card, error) {
	var (
		handle         syscall.Handle
		activeProtocol uint16
	)
	readerPtr, err := syscall.UTF16PtrFromString(reader)
	if err != nil {
		return nil, fmt.Errorf("invalid reader string: %v", err)
	}
	r0, _, _ := procSCardConnectW.Call(
		uintptr(c.ctx),
		uintptr(unsafe.Pointer(readerPtr)),
		scardShareExclusive,
		scardProtocolT1,
		uintptr(unsafe.Pointer(&handle)),
		uintptr(activeProtocol),
	)
	if err := scCheck(r0); err != nil {
		return nil, err
	}
	return &Card{handle}, nil
}

type Card struct {
	h syscall.Handle
}

func (h *Card) Close() error {
	r0, _, _ := procSCardDisconnect.Call(uintptr(h.h), scardLeaveCard)
	return scCheck(r0)
}

func (h *Card) BeginTransaction() error {
	r0, _, _ := procSCardBeginTransaction.Call(uintptr(h.h))
	return scCheck(r0)
}

func (h *Card) EndTransaction() error {
	r0, _, _ := procSCardEndTransaction.Call(uintptr(h.h), scardLeaveCard)
	return scCheck(r0)
}

func (h *Card) Transmit(req []byte) ([]byte, error) {
	var resp [maxBufferSizeExtended]byte
	reqN := len(req)
	respN := len(resp)
	r0, _, _ := procSCardTransmit.Call(
		uintptr(t.handle),
		uintptr(scardPCIT1),
		uintptr(unsafe.Pointer(&req[0])),
		uintptr(reqN),
		uintptr(0),
		uintptr(unsafe.Pointer(&resp[0])),
		uintptr(unsafe.Pointer(&respN)),
	)
	if err := scCheck(r0); err != nil {
		return false, nil, fmt.Errorf("transmitting request: %w", err)
	}
	return resp[:respN-2], nil
}
