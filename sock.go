package sctp

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

type SCTPConn struct {
	conn
}

type conn struct {
	fd *os.File        // only trough os.File we can take advantage of the runtime network poller
	rc syscall.RawConn // rc is used for specific SCTP read and write ops; derived from fd

	// mutable (by bind and bindRemove); atomic access
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

//func (c *SCTPConn) WriteMsgEor(b []byte, eor bool) (int, error) { return 0, nil }

func (c *conn) listen(ctx context.Context, laddr *SCTPAddr, backlog int, initMsg *InitMsg,
	ctrlCtxFn func(context.Context, string, string, syscall.RawConn) error) error {

	err := c.rawSetDefaultListenerSockopts()
	if err != nil {
		return err
	}
	if ctrlCtxFn != nil {
		err = ctrlCtxFn(ctx, c.ctrlNetwork(), laddr.String(), c.rc)
		if err != nil {
			return err
		}
	}
	// set init options (SCTP initMSG)
	err = c.rawSetInitOpts(initMsg)
	if err != nil {
		return err
	}
	// bind
	err = c.rawBind(laddr)
	if err != nil {
		return err
	}
	// listen
	err = c.rawListen(backlog)
	if err != nil {
		return err
	}
	// set local address
	addrs, numAddrs, err := c.rawGetLocalAddrs()
	if err != nil {
		return err
	}
	localSctpAddr, err := fromSockaddrBuff(addrs, numAddrs)
	if err != nil {
		return err
	}

	c.setAddr(localSctpAddr, nil)

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
// if the SCTP extension described in [RFC5061] is supported, adds the specified addresses to existing rawBind
func (c *conn) rawBind(laddr *SCTPAddr) error {
	const SCTP_SOCKOPT_BINDX_ADD int = 100

	buf, err := laddr.toSockaddrBuff(c.family)
	if err != nil {
		return err
	}
	/// setsockopt
	doErr := c.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptString(int(fd), SOL_SCTP, SCTP_SOCKOPT_BINDX_ADD, string(buf))
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

func (c *conn) rawListen(backlog int) error {
	var err error
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

func (c *conn) rawGetLocalAddrs() ([]byte, int, error) {
	const SCTP_GET_LOCAL_ADDRS int = 109
	return c.rawGetAddrs(SCTP_GET_LOCAL_ADDRS)
}
func (c *conn) rawGetRemoteAddrs() ([]byte, int, error) {
	const SCTP_GET_PEER_ADDRS int = 108
	return c.rawGetAddrs(SCTP_GET_PEER_ADDRS)
}

func (c *conn) rawGetAddrs(optName int) ([]byte, int, error) {
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
		return nil, 0, os.NewSyscallError("getsockopt", err)

	}
	return rawParam.addrs[:], int(rawParam.addrNum), nil
}

// serverSocket returns a conn object that is ready for
// asynchronous I/O using the network poller
func serverSocket(ctx context.Context, network string, laddr *SCTPAddr, initMsg *InitMsg,
	ctrlCtxFn func(context.Context, string, string, syscall.RawConn) error) (*conn, error) {

	family, ipv6only := favoriteAddrFamily(network, laddr, nil, "listen")
	fd, err := sysSocket(family, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		return nil, err
	}
	if err = setDefaultSockopts(fd, family, ipv6only); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "")
	if f == nil {
		_ = unix.Close(fd)
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: errors.New("os.NewFile returned nil")}
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}

	c := &conn{fd: f, rc: rc, family: family, net: network}
	if err = c.listen(ctx, laddr, listenerBacklog(), initMsg, ctrlCtxFn); err != nil {
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
