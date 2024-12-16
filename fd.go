// Copyright (c) 2024 George Yanev
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

//go:build linux

package sctp

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	_SCTP_CMSG_SNDINFO = 2
	_SCTP_CMSG_RCVINFO = 3
)

type sctpFD struct {
	f  *os.File        // only trough os.File we can take advantage of the runtime network poller
	rc syscall.RawConn // rc is used for specific SCTP socket ops; derived from fd

	// mutable (BindAdd and BindRemove); atomic access
	laddr atomic.Pointer[SCTPAddr]
	raddr atomic.Pointer[SCTPAddr]

	// immutable until Close
	family int
	net    string
}

// binds the specified addresses or, if the SCTP extension described
// in [RFC5061] is supported, adds the specified addresses to existing bind
func (fd *sctpFD) bind(laddr *SCTPAddr, bindMode int) error {
	if !fd.initialized() {
		return unix.EINVAL
	}

	var err error
	doErr := fd.rc.Control(func(s uintptr) {
		err = sysBindx(int(s), fd.family, bindMode, laddr)
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return err
	}
	fd.refreshLocalAddr()
	return nil
}

func (fd *sctpFD) listen(sysfd int, laddr *SCTPAddr, backlog int, lc *ListenConfig) error {
	var err error
	if err = setDefaultListenerSockopts(sysfd); err != nil {
		return err
	}

	if lc.Control != nil {
		c := &rawConnDummy{fd: sysfd}
		if err = lc.Control(fd.ctrlNetwork(), laddr.String(), c); err != nil {
			return err
		}
	}

	// set init options (SCTP initMSG)
	if err = setInitOptions(sysfd, lc.InitOptions); err != nil {
		return err
	}

	// bind
	if err = sysBindx(sysfd, fd.family, _SCTP_SOCKOPT_BINDX_ADD, laddr); err != nil {
		return err
	}

	// listen
	if err = sysListen(sysfd, backlog); err != nil {
		return err
	}

	// init fd (register socket with go network poller)
	if err = fd.init(sysfd); err != nil {
		return err
	}

	// set local address
	fd.refreshLocalAddr()
	return nil
}

// The tcp version of poll.FD.Accept is using readLock and prepareRead of the network poller.
// Our syscall.RawConn which is an instance of os.rawConn uses these functions in its Read func,
// but not in its Control func.
// So, we call the socket level accept function wrapped by a Read call and not by a Control call.
func (fd *sctpFD) accept() (*sctpFD, error) {
	if !fd.initialized() {
		return nil, unix.EINVAL
	}

	var err error
	var ns int
	var errcall string
	doErr := fd.rc.Read(func(fd uintptr) bool {
		for {
			ns, _, errcall, err = accept(int(fd))
			if err == nil {
				return true
			}
			switch err {
			case unix.EINTR:
				continue
			case unix.EAGAIN:
				// this causes the wrapper to call waitRead
				// see the source code for internal/poll.FD.RawRead
				return false
			case unix.ECONNABORTED:
				// This means that a socket on the listen
				// queue was closed before we Accept()ed it;
				// it's a silly error, so try again.
				continue
			}
			return true // err is set
		}
	})
	if doErr != nil {
		return nil, doErr
	}
	if err != nil {
		return nil, os.NewSyscallError(errcall, err)
	}

	newSctpFD := newFD(fd.family, fd.net)
	if err = newSctpFD.init(ns); err != nil {
		_ = unix.Close(ns)
		return nil, err
	}

	// set addresses
	newSctpFD.refreshLocalAddr()
	newSctpFD.refreshRemoteAddr()

	return newSctpFD, nil
}

func (fd *sctpFD) dial(ctx context.Context, sysfd int, raddr *SCTPAddr, d *Dialer) error {
	ctrlCtxFn := d.ControlContext
	if ctrlCtxFn == nil && d.Control != nil {
		ctrlCtxFn = func(cxt context.Context, network, address string, c syscall.RawConn) error {
			return d.Control(network, address, c)
		}
	}

	if ctrlCtxFn != nil {
		c := rawConnDummy{fd: sysfd}
		if err := ctrlCtxFn(ctx, fd.ctrlNetwork(), d.LocalAddr.String(), c); err != nil {
			return err
		}
	}

	// set SCTP initialization options
	if err := setInitOptions(sysfd, d.InitOptions); err != nil {
		return err
	}

	// if local address is not null set reuse address option and bind it
	if d.LocalAddr != nil {
		if err := setDefaultListenerSockopts(sysfd); err != nil {
			return err
		}
		// bind
		if err := sysBindx(sysfd, fd.family, _SCTP_SOCKOPT_BINDX_ADD, d.LocalAddr); err != nil {
			return err
		}
	}

	if err := fd.connect(ctx, sysfd, raddr); err != nil {
		return err
	}

	fd.refreshLocalAddr()
	fd.refreshRemoteAddr()
	return nil
}

func (fd *sctpFD) writeMsg(b []byte, info *SndInfo, to *net.IPAddr, flags int) (int, error) {
	if !fd.initialized() || (to != nil && fd.raddr.Load() == nil) {
		return 0, unix.EINVAL
	}
	var actualInfo *SndInfo
	if info != nil && info.Ppid > 0 {
		actualInfo = &SndInfo{
			Sid:     info.Sid,
			Flags:   info.Flags,
			Ppid:    Htonui32(info.Ppid), // convert to network byte order
			Context: info.Context,
			AssocId: info.AssocId,
		}
	}
	var err error
	var sa syscall.Sockaddr
	if to != nil {
		sa, err = ipToSockaddr(fd.family, to.IP, fd.raddr.Load().Port, to.Zone)
		if err != nil {
			return 0, err
		}
		if actualInfo != nil {
			actualInfo.Flags |= SCTP_ADDR_OVER
		} else {
			actualInfo = &SndInfo{Flags: SCTP_ADDR_OVER}
		}
	}
	if actualInfo == nil {
		actualInfo = info
	}

	var oob []byte
	if actualInfo != nil {
		cmsghdr := &unix.Cmsghdr{
			Level: unix.IPPROTO_SCTP,
			Type:  _SCTP_CMSG_SNDINFO,
		}
		cmsghdr.SetLen(unix.CmsgSpace(int(unsafe.Sizeof(*actualInfo))))

		cmsghdrBuf := unsafe.Slice((*byte)(unsafe.Pointer(cmsghdr)), unsafe.Sizeof(*cmsghdr))
		actualInfoBuf := unsafe.Slice((*byte)(unsafe.Pointer(actualInfo)), unsafe.Sizeof(*actualInfo))
		oob = append(cmsghdrBuf, actualInfoBuf...)
	}

	var n int
	doErr := fd.rc.Write(func(fd uintptr) (done bool) {
		for {
			n, err = syscall.SendmsgN(int(fd), b, oob, sa, flags)
			if err == nil {
				return true // err not set
			}
			switch err {
			case unix.EINTR:
				continue // ignoring EINTR
			case unix.EAGAIN:
				return false // causing waitWrite
			}
			return true // err is set
		}
	})
	if doErr != nil {
		return 0, doErr
	}
	if err != nil {
		return 0, os.NewSyscallError("sendmsg", err)
	}
	return n, nil
}

// Fills regular data or notification data in b.
// Inspect rcvFlags for SCTP_NOTIFICATION to distinguish them
// Inspect rcvFlags for SCTP_EOR to know if a whole SCTP message is read or just a part of it
func (fd *sctpFD) readMsg(b []byte) (int, *RcvInfo, int, error) {
	if !fd.initialized() {
		return 0, nil, 0, unix.EINVAL
	}
	var err error
	var n, oobn, recvFlags int
	var oob = make([]byte, 256)
	doErr := fd.rc.Read(func(fd uintptr) bool {
		for {
			n, oobn, recvFlags, _, err = syscall.Recvmsg(int(fd), b, oob, 0)
			if err == nil {
				return true // err not set
			}
			switch err {
			case unix.EINTR:
				continue // ignoring EINTR
			case unix.EAGAIN:
				return false // causing waitRead
			}
			return true // err is set
		}
	})
	if doErr != nil {
		return 0, nil, 0, doErr
	}
	if err != nil {
		return 0, nil, 0, os.NewSyscallError("recvmsg", err)
	}
	if n == 0 && oobn == 0 {
		return 0, nil, 0, io.EOF
	}

	var rcvInfo *RcvInfo
	if oobn > 0 {
		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return 0, nil, 0, err
		}
		for _, m := range msgs {
			if m.Header.Level == unix.IPPROTO_SCTP {
				switch m.Header.Type {
				case _SCTP_CMSG_RCVINFO:
					rcvInfo = (*RcvInfo)(unsafe.Pointer(&m.Data[0]))
					rcvInfo.Ppid = Ntohui32(rcvInfo.Ppid) // convert from network byte order
				}
			}
		}
	}

	return n, rcvInfo, recvFlags, nil
}

func (fd *sctpFD) refreshLocalAddr() {
	if !fd.initialized() {
		return
	}
	la, _ := fd.retrieveLocalAddr()
	fd.laddr.Store(la)
}

func (fd *sctpFD) refreshRemoteAddr() {
	if !fd.initialized() {
		return
	}
	ra, _ := fd.retrieveRemoteAddr()
	fd.raddr.Store(ra)
}

// creates an os.File, thus effectively registering the socket with the go network poller
func (fd *sctpFD) init(sysfd int) error {
	if fd.initialized() {
		return unix.EINVAL
	}

	fd.f = os.NewFile(uintptr(sysfd), "")
	if fd.f == nil {
		return errors.New("os.NewFile returned nil")
	}
	rc, err := fd.f.SyscallConn()
	if err != nil {
		_ = fd.f.Close()
		return err
	}
	fd.rc = rc
	return nil
}

func (fd *sctpFD) retrieveLocalAddr() (*SCTPAddr, error) {
	if !fd.initialized() {
		return nil, unix.EINVAL
	}
	const SCTP_GET_LOCAL_ADDRS int = 109
	return fd.retrieveAddr(SCTP_GET_LOCAL_ADDRS)
}

func (fd *sctpFD) retrieveRemoteAddr() (*SCTPAddr, error) {
	if !fd.initialized() {
		return nil, unix.EINVAL
	}
	const SCTP_GET_PEER_ADDRS int = 108
	a, err := fd.retrieveAddr(SCTP_GET_PEER_ADDRS)
	if err != nil {
		return getPeerAddr(fd)
	}
	return a, nil
}

func (fd *sctpFD) ctrlNetwork() string {
	switch fd.net[len(fd.net)-1] {
	case '4', '6':
		return fd.net
	}
	if fd.family == unix.AF_INET {
		return fd.net + "4"
	}
	return fd.net + "6"
}

func (fd *sctpFD) close() error {
	if !fd.initialized() {
		return unix.EINVAL
	}
	return fd.f.Close()
}

func (fd *sctpFD) shutdown(how int) error {
	if !fd.initialized() {
		return unix.EINVAL
	}
	var err error
	doErr := fd.rc.Control(func(fd uintptr) {
		err = unix.Shutdown(int(fd), how)
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return os.NewSyscallError("shutdown", err)
	}
	return nil
}

func (fd *sctpFD) closeRead() error {
	return fd.shutdown(unix.SHUT_RD)
}

func (fd *sctpFD) closeWrite() error {
	return fd.shutdown(unix.SHUT_WR)
}

func (fd *sctpFD) initialized() bool { return fd != nil && fd.f != nil && fd.rc != nil }

func newFD(family int, network string) *sctpFD {
	return &sctpFD{
		family: family,
		net:    network,
	}
}

// Uses getpeeraddr system call.
// Effectively gets the primary remote peer address
func getPeerAddr(fd *sctpFD) (*SCTPAddr, error) {
	var err error
	var sa unix.Sockaddr
	doErr := fd.rc.Control(func(fd uintptr) {
		sa, err = unix.Getpeername(int(fd))
	})
	if doErr != nil {
		return nil, doErr
	}
	if err != nil {
		return nil, os.NewSyscallError("getpeername", err)
	}

	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return &SCTPAddr{IPAddrs: []net.IPAddr{{IP: a.Addr[:]}}, Port: a.Port}, nil
	case *unix.SockaddrInet6:
		return &SCTPAddr{IPAddrs: []net.IPAddr{{IP: a.Addr[:], Zone: zoneCache.name(int(a.ZoneId))}}, Port: a.Port}, nil
	default:
		return nil, os.NewSyscallError("getpeername", fmt.Errorf("unsupported sockaddr type: %T", sa))
	}
}
