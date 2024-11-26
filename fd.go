package sctp

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"log"
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

	// mutable (by BindAdd and BindRemove); atomic access
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
	if err = setInitOpts(sysfd, &lc.InitMsg); err != nil {
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

	if _, err = syscall.Getpeername(ns); err != nil {
		log.Printf("Getpeername from ACCEPT returned error: %v", err)
	} else {
		log.Printf("Getpeername from ACCEPT returned OK")
	}
	// set addresses
	newSctpFD.refreshLocalAddr()
	newSctpFD.refreshRemoteAddr()

	return newSctpFD, nil
}

func (fd *sctpFD) dial(ctx context.Context, s int, laddr *SCTPAddr, raddr *SCTPAddr, initMsg *InitMsg,
	ctrlCtxFn func(context.Context, string, string, syscall.RawConn) error) error {
	log.Printf("gId: %d, func fd.dial", getGoroutineID())

	if ctrlCtxFn != nil {
		c := rawConnDummy{fd: s}
		if err := ctrlCtxFn(ctx, fd.ctrlNetwork(), laddr.String(), c); err != nil {
			return err
		}
	}

	// set SCTP initialization options
	if err := setInitOpts(s, initMsg); err != nil {
		return err
	}

	// if local address is not null set reuse address option and bind it
	if laddr != nil {
		if err := setDefaultListenerSockopts(s); err != nil {
			return err
		}
		// bind
		if err := sysBindx(s, fd.family, _SCTP_SOCKOPT_BINDX_ADD, laddr); err != nil {
			return err
		}
	}

	if err := fd.connect(ctx, s, raddr); err != nil {
		return err
	}

	fd.refreshLocalAddr()
	fd.refreshRemoteAddr()
	return nil
}

func (fd *sctpFD) writeMsg(b []byte, info *SndInfo, to *net.IPAddr, flags int) (int, error) {
	if !fd.initialized() || (to != nil && fd.raddr.Load() == nil) {
		return 0, errEINVAL
	}
	var err error
	var sa syscall.Sockaddr
	if to != nil {
		sa, err = ipToSockaddr(fd.family, to.IP, fd.raddr.Load().Port, to.Zone)
		if err != nil {
			return 0, err
		}
		if info != nil {
			info.Flags |= SCTP_ADDR_OVER
		} else {
			info = &SndInfo{Flags: SCTP_ADDR_OVER}
		}
	}
	var oob []byte
	if info != nil {
		cmsghdr := &unix.Cmsghdr{
			Level: unix.IPPROTO_SCTP,
			Type:  _SCTP_CMSG_SNDINFO,
		}
		cmsghdr.SetLen(unix.CmsgSpace(int(unsafe.Sizeof(*info))))

		cmsghdrBuf := unsafe.Slice((*byte)(unsafe.Pointer(cmsghdr)), unsafe.Sizeof(*cmsghdr))
		infoBuf := unsafe.Slice((*byte)(unsafe.Pointer(info)), unsafe.Sizeof(*info))
		oob = append(cmsghdrBuf, infoBuf...)
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

func (fd *sctpFD) readMsg(b []byte, flags int) (int, *RcvInfo, error) {
	if !fd.initialized() {
		return 0, nil, errEINVAL
	}
	var err error
	var n, oobn, recvflags int
	var oob = make([]byte, 256)
	doErr := fd.rc.Read(func(fd uintptr) bool {
		for {
			n, oobn, recvflags, _, err = syscall.Recvmsg(int(fd), b, oob, flags)
			if err == nil {
				if recvflags&SCTP_NOTIFICATION > 0 {
					log.Printf("This is a notification")
					continue
				}
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
		return 0, nil, doErr
	}
	if err != nil {
		return 0, nil, os.NewSyscallError("recvmsg", err)
	}
	if n == 0 && oobn == 0 {
		return 0, nil, io.EOF
	}

	var rcvInfo *RcvInfo
	if oobn > 0 {
		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return 0, nil, err
		}
		for _, m := range msgs {
			if m.Header.Level == unix.IPPROTO_SCTP {
				switch m.Header.Type {
				case _SCTP_CMSG_RCVINFO:
					rcvInfo = (*RcvInfo)(unsafe.Pointer(&m.Data[0]))
				}
			}
		}
	}
	return n, rcvInfo, nil
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
	if !fd.initialized() {
		return nil, errEINVAL
	}

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
		err = getsockoptBytes(int(fd), unix.IPPROTO_SCTP, optName, rawParamBuf)
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
