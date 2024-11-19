package sctp

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"
)

type sctpFD struct {
	f  *os.File        // only trough os.File we can take advantage of the runtime network poller
	rc syscall.RawConn // rc is used for specific SCTP socket ops; derived from fd

	// mutable (by BindAdd and BindRemove); atomic access
	laddr atomic.Pointer[SCTPAddr]
	raddr atomic.Pointer[SCTPAddr]

	// immutable until Close
	family int
	net    string
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

// binds the specified addresses or, if the SCTP extension described
// in [RFC5061] is supported, adds the specified addresses to existing bind
func (fd *sctpFD) bind(laddr *SCTPAddr, bindMode int) error {
	if !fd.initialized() {
		return errEINVAL
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

func (fd *sctpFD) listen(ctx context.Context, sysfd int, laddr *SCTPAddr, backlog int, initMsg *InitMsg,
	ctrlCtxFn func(context.Context, string, string, syscall.RawConn) error) error {
	var err error
	if err = setDefaultListenerSockopts(sysfd); err != nil {
		return err
	}

	if ctrlCtxFn != nil {
		c := &rawConnDummy{fd: sysfd}
		if err = ctrlCtxFn(ctx, fd.ctrlNetwork(), laddr.String(), c); err != nil {
			return err
		}
	}

	// set init options (SCTP initMSG)
	if err = setInitOpts(sysfd, initMsg); err != nil {
		return err
	}

	// bind
	if err = sysBindx(sysfd, fd.family, SCTP_SOCKOPT_BINDX_ADD, laddr); err != nil {
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
		return nil, errEINVAL
	}

	var err error
	var ns int
	var errcall string
	doErr := fd.rc.Read(func(fd uintptr) bool {
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
		return errEINVAL
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
		return nil, errEINVAL
	}

	const SCTP_GET_LOCAL_ADDRS int = 109
	log.Printf("gId: %d, func rawGetLocalAddr\n", getGoroutineID())
	return fd.retrieveAddr(SCTP_GET_LOCAL_ADDRS)
}

func (fd *sctpFD) retrieveRemoteAddr() (*SCTPAddr, error) {
	if !fd.initialized() {
		return nil, errEINVAL
	}

	const SCTP_GET_PEER_ADDRS int = 108
	log.Printf("gId: %d, func rawGetRemoteAddr\n", getGoroutineID())
	return fd.retrieveAddr(SCTP_GET_PEER_ADDRS)
}

func (fd *sctpFD) retrieveAddr(optName int) (*SCTPAddr, error) {
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
	doErr := fd.rc.Control(func(fd uintptr) {
		err = getsockoptBytes(int(fd), SOL_SCTP, optName, rawParamBuf)
	})
	if doErr != nil {
		return nil, doErr
	}
	if err != nil {
		log.Printf("gId: %d, getsockopt error: %v, optName: %v, rawParamBuf: %v ", getGoroutineID(), err, optName, rawParamBuf)
		//debug.PrintStack()
		return nil, os.NewSyscallError("getsockopt", err)
	}

	sctpAddr, err := fromSockaddrBuff(rawParam.addrs[:], int(rawParam.addrNum))
	if err != nil {
		return nil, err
	}

	return sctpAddr, nil
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
		return errEINVAL
	}
	return fd.f.Close()
}

func (fd *sctpFD) initialized() bool { return fd != nil && fd.f != nil && fd.rc != nil }

func newFD(family int, network string) *sctpFD {
	return &sctpFD{
		family: family,
		net:    network,
	}
}
