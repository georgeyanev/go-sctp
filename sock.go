package sctp

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

type conn struct {
	fd *os.File        // only trough os.File we can take advantage of the runtime network poller
	rc syscall.RawConn // rc is used for specific SCTP socket ops; derived from fd

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
		if err = ctrlCtxFn(ctx, ctrlNetwork(c.family, c.net), laddr.String(), c.rc); err != nil {
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

func (c *conn) ok() bool { return c != nil && c.fd != nil }

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
	return c.rawBind(laddr, SCTP_SOCKOPT_BINDX_ADD)
}

func (c *conn) rawBindRemove(laddr *SCTPAddr) error {
	return c.rawBind(laddr, SCTP_SOCKOPT_BINDX_REM)
}

func (c *conn) rawBind(laddr *SCTPAddr, bindMode int) error {
	var err error
	doErr := c.rc.Control(func(fd uintptr) {
		err = sysBindx(int(fd), c.family, bindMode, laddr)
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return err
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
