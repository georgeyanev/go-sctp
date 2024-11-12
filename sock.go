package sctp

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

type conn struct {
	fd *os.File        // only trough os.File we can take advantage of the runtime network poller
	rc syscall.RawConn // rc is used for specific SCTP read and write ops; derived from fd

	// mutable (by BindAdd and BindRemove); atomic access
	laddr atomic.Pointer[SCTPAddr]
	raddr atomic.Pointer[SCTPAddr]

	// immutable until Close
	family int
	net    string
}

func (c *conn) Read(b []byte) (int, error) { return c.fd.Read(b) }

func (c *conn) Write(b []byte) (int, error) { return c.fd.Write(b) }

func (c *conn) SetDeadline(t time.Time) error { return c.fd.SetDeadline(t) }

func (c *conn) SetReadDeadline(t time.Time) error { return c.fd.SetReadDeadline(t) }

func (c *conn) SetWriteDeadline(t time.Time) error { return c.fd.SetWriteDeadline(t) }

func (c *conn) Close() error { return c.fd.Close() }

func (c *conn) LocalAddr() net.Addr { return c.laddr.Load() }

func (c *conn) RemoteAddr() net.Addr { return c.raddr.Load() }

// TODO: write SCTP specific functions, i.e. specifying EOF upon return, specifying input/output stream etc.
// bool is EOR

func (c *SCTPConn) ReadMsg(b []byte) (int, bool, error) { return 0, true, nil }
func (c *SCTPConn) WriteMsg(b []byte) (int, error)      { return 0, nil }

//func (c *Conn) WriteMsgEor(b []byte, eor bool) (int, error) { return 0, nil }

func (c *conn) listen(ctx context.Context, laddr *SCTPAddr, backlog int, initMsg *InitMsg,
	ctrlCtxFn func(context.Context, string, string, syscall.RawConn) error) error {

	log.Printf("gId: %d, func c.listen", getGoroutineID())
	var err error
	if err = c.rawSetDefaultListenerSockopts(); err != nil {
		return err
	}
	if ctrlCtxFn != nil {
		if err = ctrlCtxFn(ctx, c.ctrlNetwork(), laddr.String(), c.rc); err != nil {
			return err
		}
	}
	// set init options (SCTP initMSG)
	if err = c.rawSetInitOpts(initMsg); err != nil {
		return err
	}
	// bind
	if err = c.rawBindAdd(laddr); err != nil {
		return err
	}
	// listen
	if err = c.rawListen(backlog); err != nil {
		return err
	}
	// set local address
	la, _ := c.getLocalAddr()
	c.setAddr(la, nil)
	return nil
}

func (c *conn) dial(ctx context.Context, laddr *SCTPAddr, raddr *SCTPAddr, msg *InitMsg,
	ctrlCtxFn func(context.Context, string, string, syscall.RawConn) error) error {

	log.Printf("gId: %d, func c.dial", getGoroutineID())

	var err error
	if ctrlCtxFn != nil {
		if err = ctrlCtxFn(ctx, c.ctrlNetwork(), raddr.String(), c.rc); err != nil {
			return err
		}
	}

	// if local address is not null set reuse address option and bind it
	if laddr != nil {
		if err = c.rawSetDefaultListenerSockopts(); err != nil {
			return err
		}
		// bind
		if err = c.rawBindAdd(laddr); err != nil {
			return err
		}
	}
	// connect
	if err = c.connect(ctx, raddr); err != nil {
		return err
	}

	// set local and remote addresses
	var la, ra *SCTPAddr
	la, _ = c.getLocalAddr()
	ra, _ = c.getRemoteAddr()
	c.setAddr(la, ra)
	return nil
}

func (c *conn) rawConnect(raddr *SCTPAddr) error {
	// In one-to-one SCTP mode (SOCK_STREAM socket type) we don't want the
	// association-id so it is safe to use the "old" connect api.
	// Moreover, the association-id can be provided only if the socket is in
	// blocking mode which is not our case.
	const SCTP_SOCKOPT_CONNECTX_OLD = 107

	log.Printf("gId: %d, func rawConnect", getGoroutineID())

	// accommodate wildcard addresses to point to local system
	var finalRaddr *SCTPAddr
	if raddr.isWildcard() && c.family == syscall.AF_INET {
		finalRaddr = &SCTPAddr{
			Port:    raddr.Port,
			IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}},
		}
	} else if raddr.isWildcard() && c.family == syscall.AF_INET6 {
		finalRaddr = &SCTPAddr{
			Port:    raddr.Port,
			IPAddrs: []net.IPAddr{{IP: net.IPv6loopback}},
		}
	} else {
		finalRaddr = raddr
	}

	buf, err := finalRaddr.toSockaddrBuff(c.family)
	if err != nil {
		return err
	}
	// setsockopt
	doErr := c.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptString(int(fd), SOL_SCTP, SCTP_SOCKOPT_CONNECTX_OLD, string(buf))
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return err // we can not wrap here because we switch over this value
	}
	return nil
}

func (c *conn) ctrlNetwork() string {
	switch c.net[len(c.net)-1] {
	case '4', '6':
		return c.net
	}
	if c.family == syscall.AF_INET {
		return c.net + "4"
	}
	return c.net + "6"
}

func (c *conn) setAddr(laddr, raddr *SCTPAddr) {
	c.laddr.Store(laddr)
	c.raddr.Store(raddr)
}

func (c *conn) getLocalAddr() (*SCTPAddr, error) {
	laddr, numAddrs, err := c.rawGetLocalAddr()
	if err != nil {
		return nil, err
	}
	localSctpAddr, err := fromSockaddrBuff(laddr, numAddrs)
	if err != nil {
		return nil, err
	}
	return localSctpAddr, nil
}

func (c *conn) getRemoteAddr() (*SCTPAddr, error) {
	raddr, numAddrs, err := c.rawGetRemoteAddr()
	if err != nil {
		return nil, err
	}
	remoteSctpAddr, err := fromSockaddrBuff(raddr, numAddrs)
	if err != nil {
		return nil, err
	}
	return remoteSctpAddr, nil
}

func (c *conn) ok() error {
	if c == nil {
		return errEINVAL // or os.ErrInvalid ?
	}
	return nil
}

func (c *conn) accept() (*conn, error) {
	nfd, err := c.rawAccept()
	if err != nil {
		return nil, err
	}

	nc, err := newConn(nfd, c.family, c.net)
	if err != nil {
		return nil, err
	}

	// get local and remote addresses
	var la, ra *SCTPAddr
	la, _ = nc.getLocalAddr()
	log.Printf("gId: %d, la: %v\n", getGoroutineID(), la)
	ra, _ = nc.getRemoteAddr()
	log.Printf("gId: %d, ra: %v\n", getGoroutineID(), ra)
	// set local and remote addresses
	nc.setAddr(la, ra)
	return nc, nil
}

func (c *conn) rawSetDefaultListenerSockopts() error {
	var err error
	doErr := c.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

// sets init options with setsockopt
func (c *conn) rawSetInitOpts(initMsg *InitMsg) error {
	const SCTP_INITMSG = 2

	var err error
	initMsgBuf := unsafe.Slice((*byte)(unsafe.Pointer(initMsg)), unsafe.Sizeof(*initMsg))
	/// setsockopt
	doErr := c.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptString(int(fd), SOL_SCTP, SCTP_INITMSG, string(initMsgBuf))
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

// rawBind binds the specified addresses or,
// if the SCTP extension described in [RFC5061] is supported, adds the specified addresses to existing bind
func (c *conn) rawBindAdd(laddr *SCTPAddr) error {
	const SCTP_SOCKOPT_BINDX_ADD int = 100
	return c.rawBind(laddr, SCTP_SOCKOPT_BINDX_ADD)
}

func (c *conn) rawBindRemove(laddr *SCTPAddr) error {
	const SCTP_SOCKOPT_BINDX_REM int = 101
	return c.rawBind(laddr, SCTP_SOCKOPT_BINDX_REM)
}

func (c *conn) rawBind(laddr *SCTPAddr, bindMode int) error {
	buf, err := laddr.toSockaddrBuff(c.family)
	if err != nil {
		return err
	}
	/// setsockopt
	doErr := c.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptString(int(fd), SOL_SCTP, bindMode, string(buf))
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return os.NewSyscallError("bindx", err)
	}
	return nil
}

func (c *conn) rawListen(backlog int) error {
	var err error
	log.Printf("gId: %d, func rawListen\n", getGoroutineID())
	doErr := c.rc.Control(func(fd uintptr) {
		err = unix.Listen(int(fd), backlog)
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return os.NewSyscallError("listen", err)
	}
	return nil
}
func (c *conn) rawGetLocalAddr() ([]byte, int, error) {
	const SCTP_GET_LOCAL_ADDRS int = 109
	log.Printf("gId: %d, func rawGetLocalAddr\n", getGoroutineID())
	return c.rawGetAddrs(SCTP_GET_LOCAL_ADDRS)
}

func (c *conn) rawGetRemoteAddr() ([]byte, int, error) {
	const SCTP_GET_PEER_ADDRS int = 108
	log.Printf("gId: %d, func rawGetRemoteAddr\n", getGoroutineID())
	return c.rawGetAddrs(SCTP_GET_PEER_ADDRS)
}

func (c *conn) rawGetAddrs(optName int) ([]byte, int, error) {
	// SCTP_ADDRS_BUF_SIZE is the allocated buffer for system calls returning local/remote sctp multi-homed addresses
	const SCTP_ADDRS_BUF_SIZE int = 4096 //enough for most cases

	log.Printf("gId: %d,func rawGetAddrs\n", getGoroutineID())

	type rawSctpAddrs struct {
		assocId int32
		addrNum uint32
		addrs   [SCTP_ADDRS_BUF_SIZE]byte
	}
	rawParam := rawSctpAddrs{} // to be filled by the getsockopt call

	var err error
	rawParamBuf := unsafe.Slice((*byte)(unsafe.Pointer(&rawParam)), unsafe.Sizeof(rawParam))
	doErr := c.rc.Control(func(fd uintptr) {
		err = getsockoptBytes(int(fd), SOL_SCTP, optName, rawParamBuf)
	})
	if doErr != nil {
		return nil, 0, doErr
	}
	if err != nil {
		log.Printf("gId: %d, getsockopt error: %v, optName: %v, rawParamBuf: %v ", getGoroutineID(), err, optName, rawParamBuf)
		//debug.PrintStack()
		return nil, 0, os.NewSyscallError("getsockopt", err)
	}
	return rawParam.addrs[:], int(rawParam.addrNum), nil
}

// The tcp version of raw accept (i.e. poll.FD.Accept) is using readLock and prepareRead of the network poller.
// Our syscall.RawConn which is an instance of os.rawConn uses these functions in its Read func, but not in its Control func.
// Thus, we call the socket level accept function wrapped by a Read call and not a Control call.
func (c *conn) rawAccept() (int, error) {
	var err error
	var ns int
	var errcall string
	doErr := c.rc.Read(func(fd uintptr) bool {
		for {
			ns, _, errcall, err = accept(int(fd))
			log.Printf("gId: %d, rawAccept returned %d", getGoroutineID(), err)
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
		return -1, doErr
	}
	if err != nil {
		return -1, os.NewSyscallError(errcall, err)
	}
	return ns, nil
}

func (c *conn) rawSetNoDelay(b bool) error {
	const SCTP_NODELAY int = 3

	var err error
	doErr := c.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.IPPROTO_SCTP, SCTP_NODELAY, boolint(b))
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

func (c *conn) rawGetpeername() (unix.Sockaddr, error) {
	var err error
	var rsa unix.Sockaddr
	doErr := c.rc.Control(func(fd uintptr) {
		rsa, err = unix.Getpeername(int(fd))
	})
	if doErr != nil {
		return nil, doErr
	}
	if err != nil {
		return nil, os.NewSyscallError("getpeername", err)
	}
	return rsa, nil
}

func newConn(fd, family int, net string) (*conn, error) {
	f := os.NewFile(uintptr(fd), "")
	if f == nil {
		_ = unix.Close(fd)
		return nil, errors.New("os.NewFile returned nil")
	}
	rc, err := f.SyscallConn()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	c := &conn{fd: f, rc: rc, family: family, net: net}
	return c, nil
}

func newSCTPConn(c *conn) *SCTPConn {
	_ = c.rawSetNoDelay(true)

	// TO DO: set heartbeat disable here or heartbeat interval
	return &SCTPConn{c}
}

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

	if err = setDefaultSockopts(fd, family, ipv6only); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

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

// serverSocket returns a listening conn object that is ready for
// asynchronous I/O using the network poller
func clientSocket(ctx context.Context, network string, laddr, raddr *SCTPAddr, initMsg *InitMsg,
	ctrlCtxFn func(context.Context, string, string, syscall.RawConn) error) (*conn, error) {

	log.Printf("gId: %d, func clientSocket", getGoroutineID())

	family, ipv6only := favoriteAddrFamily(network, laddr, raddr, "dial")
	fd, err := sysSocket(family, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		return nil, err
	}

	if err = setDefaultSockopts(fd, family, ipv6only); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	c, err := newConn(fd, family, network)
	if err != nil {
		return nil, err
	}

	if err = c.dial(ctx, laddr, raddr, initMsg, ctrlCtxFn); err != nil {
		_ = c.Close()
		return nil, err
	}

	return c, nil
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
