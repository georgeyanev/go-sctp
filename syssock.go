package sctp

import (
	"context"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// serverSocket returns a listening conn object that is ready for
// asynchronous I/O using the network poller
func serverSocket(ctx context.Context, network string, laddr *SCTPAddr, initMsg *InitMsg,
	ctrlCtxFn func(context.Context, string, string, syscall.RawConn) error) (*conn, error) {

	log.Printf("gId: %d,func serverSocket", getGoroutineID())

	family, ipv6only := favoriteAddrFamily(network, laddr, nil, "listen")
	fd, err := sysSocket(family, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		return nil, err
	}

	_ = setDefaultSockopts(fd, family, ipv6only)

	c, err := newConn(fd, family, network)
	if err != nil {
		return nil, err
	}

	if err = c.listen(ctx, laddr, listenerBacklog(), initMsg, ctrlCtxFn); err != nil {
		_ = c.Close()
		return nil, err
	}

	return c, nil
}

// clientSocket returns a listening conn object that is ready for
// asynchronous I/O using the network poller
func clientSocket(ctx context.Context, network string, laddr, raddr *SCTPAddr, initMsg *InitMsg,
	ctrlCtxFn func(context.Context, string, string, syscall.RawConn) error) (*conn, error) {

	log.Printf("gId: %d, func clientSocket", getGoroutineID())

	family, ipv6only := favoriteAddrFamily(network, laddr, raddr, "dial")
	fd, err := sysSocket(family, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		return nil, err
	}

	_ = setDefaultSockopts(fd, family, ipv6only)

	return sysDial(fd, family, network, ctx, laddr, raddr, initMsg, ctrlCtxFn)
}

type rawConnDummy struct {
	fd int
}

func (r rawConnDummy) Control(f func(uintptr)) error {
	f(uintptr(r.fd))
	return nil
}

func (r rawConnDummy) Read(f func(uintptr) bool) error {
	panic("not implemented")
}

func (r rawConnDummy) Write(f func(uintptr) bool) error {
	panic("not implemented")
}

func sysDial(fd, family int, network string, ctx context.Context, laddr *SCTPAddr, raddr *SCTPAddr, msg *InitMsg,
	ctrlCtxFn func(context.Context, string, string, syscall.RawConn) error) (*conn, error) {
	log.Printf("gId: %d, func sysDial", getGoroutineID())

	if ctrlCtxFn != nil {
		c := rawConnDummy{fd: fd}
		if err := ctrlCtxFn(ctx, ctrlNetwork(family, network), laddr.String(), c); err != nil {
			return nil, err
		}
	}

	// set SCTP initialization options
	if err := setInitOpts(fd, msg); err != nil {
		return nil, err
	}

	// if local address is not null set reuse address option and bind it
	if laddr != nil {
		if err := setDefaultListenerSockopts(fd); err != nil {
			return nil, err
		}
		// bind
		if err := bindx(fd, family, SCTP_SOCKOPT_BINDX_ADD, laddr); err != nil {
			return nil, err
		}
	}

	c, err := connect(fd, family, network, ctx, raddr)
	if err != nil {
		return nil, err
	}

	// set local and remote addresses
	var la, ra *SCTPAddr
	la, _ = c.getLocalAddr()
	ra, _ = c.getRemoteAddr()
	c.setAddr(la, ra)
	return c, nil
}

func setInitOpts(fd int, initMsg *InitMsg) error {
	const SCTP_INITMSG = 2
	initMsgBuf := unsafe.Slice((*byte)(unsafe.Pointer(initMsg)), unsafe.Sizeof(*initMsg))
	return os.NewSyscallError("setsockopt", unix.SetsockoptString(int(fd), SOL_SCTP, SCTP_INITMSG, string(initMsgBuf)))
}

func bindx(fd, family, bindMode int, laddr *SCTPAddr) error {
	buf, err := laddr.toSockaddrBuff(family)
	if err != nil {
		return &net.AddrError{Err: err.Error(), Addr: laddr.String()}
	}
	return os.NewSyscallError("bindx", unix.SetsockoptString(fd, SOL_SCTP, bindMode, string(buf)))
}

func rawConnect(fd, family int, raddr *SCTPAddr) error {
	const SCTP_SOCKOPT_CONNECTX = 110

	log.Printf("gId: %d, func rawConnect", getGoroutineID())

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
	if err = unix.SetsockoptString(fd, SOL_SCTP, SCTP_SOCKOPT_CONNECTX, string(buf)); err != nil {
		return err // we can not wrap here because we switch over this value
	}
	return nil
}

func getsockoptBytes(fd, level, opt int, b []byte) error {
	p := unsafe.Pointer(&b[0])
	vallen := uint32(len(b))

	if runtime.GOARCH == "s390x" || runtime.GOARCH == "386" {
		const (
			SYS_SOCKETCALL = 102
			_GETSOCKOPT    = 15
		)
		args := [5]uintptr{uintptr(fd), uintptr(level), uintptr(opt), uintptr(p), uintptr(unsafe.Pointer(&vallen))}
		_, _, err := unix.Syscall(SYS_SOCKETCALL, _GETSOCKOPT, uintptr(unsafe.Pointer(&args)), 0)
		if err != 0 {
			return errnoErr(err)
		}
		return nil
	}

	_, _, e1 := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt), uintptr(p), uintptr(unsafe.Pointer(&vallen)), 0)
	if e1 != 0 {
		return errnoErr(e1)
	}
	return nil
}

func ctrlNetwork(family int, network string) string {
	switch network[len(network)-1] {
	case '4', '6':
		return network
	}
	if family == syscall.AF_INET {
		return network + "4"
	}
	return network + "6"
}
