// Copyright (c) 2024 George Yanev
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

//go:build !linux

package sctp

import (
	"context"
	"errors"
	"net"
	"runtime"
	"syscall"
	"time"
)

var ErrNotSupported = errors.New("go-sctp is not supported on " + runtime.GOOS)

var errNoSuitableAddress = errors.New("no suitable address found")

func ipToSockaddrInet4(ip net.IP, port int) (syscall.SockaddrInet4, error) {
	return syscall.SockaddrInet4{}, ErrNotSupported
}

func sockaddrInet4ToBuf(sa4 syscall.SockaddrInet4) ([]byte, error) {
	return nil, ErrNotSupported
}

func ipToSockaddrInet6(ip net.IP, port int, zone string) (syscall.SockaddrInet6, error) {
	return syscall.SockaddrInet6{}, ErrNotSupported
}

func sockaddrInet6ToBuf(sa6 syscall.SockaddrInet6) ([]byte, error) {
	return nil, ErrNotSupported
}

func fromSockaddrBuff(buf []byte, numAddrs int) (*SCTPAddr, error) {
	return nil, ErrNotSupported
}

func (fd *sctpFD) close() error {
	return ErrNotSupported
}

func (fd *sctpFD) bindAdd(laddr *SCTPAddr) error {
	return ErrNotSupported
}

func (fd *sctpFD) bindRemove(laddr *SCTPAddr) error {
	return ErrNotSupported
}

func (fd *sctpFD) readMsg(b, oob []byte) (int, *RcvInfo, int, error) {
	return 0, nil, 0, ErrNotSupported
}

func (fd *sctpFD) writeMsg(b []byte, info *SndInfo, to *net.IPAddr, flags int) (int, error) {
	return 0, ErrNotSupported
}

func (fd *sctpFD) subscribe(event EventType, enabled bool) error {
	return ErrNotSupported
}

func (fd *sctpFD) refreshRemoteAddr() {}

func (fd *sctpFD) setNoDelay(b bool) error {
	return ErrNotSupported
}

func (fd *sctpFD) setDisableFragments(b bool) error {
	return ErrNotSupported
}

func (fd *sctpFD) writeBufferSize() (int, error) {
	return 0, ErrNotSupported
}

func (fd *sctpFD) readBufferSize() (int, error) {
	return 0, ErrNotSupported
}

func (fd *sctpFD) setLinger(sec int) error {
	return ErrNotSupported
}

func (fd *sctpFD) closeRead() error {
	return ErrNotSupported
}

func (fd *sctpFD) status(to *net.IPAddr) (*Status, error) {
	return nil, ErrNotSupported
}

func (fd *sctpFD) closeWrite() error {
	return ErrNotSupported
}

func (fd *sctpFD) setCookieLife(d time.Duration) error {
	return ErrNotSupported
}

func (fd *sctpFD) setHeartbeat(d time.Duration, to *net.IPAddr) error {
	return ErrNotSupported
}

func (fd *sctpFD) assocInfo() (*AssocParams, error) {
	return nil, ErrNotSupported
}

func (d *Dialer) DialSCTPContext(ctx context.Context, network string, raddr *SCTPAddr) (*SCTPConn, error) {
	return nil, ErrNotSupported
}

func serverSocket(network string, laddr *SCTPAddr, lc *ListenConfig) (fd *sctpFD, err error) {
	return nil, ErrNotSupported
}

func (fd *sctpFD) accept() (*sctpFD, error) {
	return nil, ErrNotSupported
}
