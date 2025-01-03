// Copyright (c) 2024 George Yanev
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

//go:build linux

package sctp

import (
	"context"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"syscall"
)

// serverSocket returns a listening sctpFD object that is ready for
// asynchronous I/O using the network poller
func serverSocket(network string, laddr *SCTPAddr, lc *ListenConfig) (fd *sctpFD, err error) {
	family, ipv6only := favoriteAddrFamily(network, laddr, nil, "listen")
	s, err := sysSocket(family, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		return nil, err
	}

	if err = setDefaultSockopts(s, family, ipv6only); err != nil {
		_ = unix.Close(s)
		return nil, err
	}

	fd = newFD(family, network)
	if err = fd.listen(s, laddr, listenerBacklog(), lc); err != nil {
		_ = unix.Close(s)
		return nil, err
	}
	return
}

// serverSocket returns a listening sctpFD object that is ready for
// asynchronous I/O using the network poller
func clientSocket(ctx context.Context, network string, raddr *SCTPAddr, d *Dialer) (fd *sctpFD, err error) {
	family, ipv6only := favoriteAddrFamily(network, d.LocalAddr, raddr, "dial")
	s, err := sysSocket(family, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		return nil, err
	}

	if err = setDefaultSockopts(s, family, ipv6only); err != nil {
		_ = unix.Close(s)
		return nil, err
	}

	fd = newFD(family, network)
	if err = fd.dial(ctx, s, raddr, d); err != nil {
		_ = unix.Close(s)
		return nil, err
	}
	return
}

func sysBindx(fd, family, bindMode int, laddr *SCTPAddr) error {
	buf, err := laddr.toSockaddrBuff(family)
	if err != nil {
		return &net.AddrError{Err: err.Error(), Addr: laddr.String()}
	}
	return os.NewSyscallError("bindx", unix.SetsockoptString(fd, unix.IPPROTO_SCTP, bindMode, string(buf)))
}

func sysListen(sysfd, backlog int) error {
	return os.NewSyscallError("listen", unix.Listen(sysfd, backlog))
}

func sysConnect(fd, family int, raddr *SCTPAddr) error {
	const SCTP_SOCKOPT_CONNECTX = 110

	// accommodate wildcard addresses to point to local system
	var finalRaddr *SCTPAddr
	if raddr.isWildcard() && family == syscall.AF_INET {
		finalRaddr = &SCTPAddr{
			Port:    raddr.Port,
			IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}},
		}
	} else if raddr.isWildcard() && family == syscall.AF_INET6 {
		finalRaddr = &SCTPAddr{
			Port:    raddr.Port,
			IPAddrs: []net.IPAddr{{IP: net.IPv6loopback}},
		}
	} else {
		finalRaddr = raddr
	}

	buf, err := finalRaddr.toSockaddrBuff(family)
	if err != nil {
		return &net.AddrError{Err: err.Error(), Addr: finalRaddr.String()}
	}
	// in one-to-one SCTP mode (SOCK_STREAM socket type) we don't want the assoc_id
	if err = unix.SetsockoptString(fd, unix.IPPROTO_SCTP, SCTP_SOCKOPT_CONNECTX, string(buf)); err != nil {
		return err // we can not wrap here because we switch over this value
	}
	return nil
}

// used in calling ControlFn functions with Listen and Dial
type rawConnDummy struct {
	fd int
}

func (r rawConnDummy) Control(f func(uintptr)) error {
	f(uintptr(r.fd))
	return nil
}

func (r rawConnDummy) Read(_ func(uintptr) bool) error {
	panic("not implemented")
}

func (r rawConnDummy) Write(_ func(uintptr) bool) error {
	panic("not implemented")
}
