package sctp

import (
	"golang.org/x/sys/unix"
	"log"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	_SCTP_INITMSG           = 2
	_SCTP_NODELAY           = 3
	_SCTP_DISABLE_FRAGMENTS = 8
	_SCTP_MAXSEG            = 13
	_SCTP_SOCKOPT_BINDX_ADD = 100
	_SCTP_SOCKOPT_BINDX_REM = 101
)

// InitMsg structure provides information for initializing new SCTP associations
type InitMsg struct {
	// number of streams to which the application wishes to be able to send, 10 by default
	NumOstreams uint16
	// maximum number of inbound streams the application is prepared to support, 10 by default
	MaxInstreams uint16
	// how many attempts the SCTP endpoint should make at resending the INIT
	// if not specified the kernel parameter net.sctp.max_init_retransmits is used as default
	MaxAttempts uint16
	// largest timeout or retransmission timeout (RTO) value (in milliseconds) to use in attempting an INIT
	// if not specified the kernel parameter net.sctp.rto_max is used as default
	MaxInitTimeout uint16
}

type assocValue struct {
	// association id, ignored for one-to-one style sockets
	assocId int32
	// association parameter value (can be SCTP_MAXSEG, SCTP_MAX_BURST, SCTP_CONTEXT)
	assocValue uint32
}

// Changes: set default options for SCTP only
// Note that SCTP is connection-oriented in nature, and it does not support broadcast or multicast
// communications, as UDP does.
func setDefaultSockopts(s, family int, ipv6only bool) error {
	if family == syscall.AF_INET6 {
		// Allow both IP versions even if the OS default
		// is otherwise. Note that some operating systems
		// never admit this option.
		_ = syscall.SetsockoptInt(s, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, boolint(ipv6only))

		//// set PMTU discovery option
		//err := syscall.SetsockoptInt(s, syscall.IP_PROTO_IP, syscall.IPV6_MTU_DISCOVER, syscall.IP_PMTUDISC_DO)
		//if err != nil {
		//	return os.NewSyscallError("setsockopt", err)
		//}
	} else {
		//// set PMTU discovery option
		//err := syscall.SetsockoptInt(s, syscall.IP_PROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO)
		//if err != nil {
		//	return os.NewSyscallError("setsockopt", err)
		//}
	}
	return nil
}

func setDefaultListenerSockopts(s int) error {
	// Allow reuse of recently-used addresses.
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1))
}

func setInitOpts(fd int, initMsg *InitMsg) error {
	initMsgBuf := unsafe.Slice((*byte)(unsafe.Pointer(initMsg)), unsafe.Sizeof(*initMsg))
	return os.NewSyscallError("setsockopt", unix.SetsockoptString(int(fd), unix.IPPROTO_SCTP, _SCTP_INITMSG, string(initMsgBuf)))
}

func (fd *sctpFD) getNoDelay() (bool, error) {
	if !fd.initialized() {
		return false, errEINVAL
	}

	var err error
	var optVal int
	doErr := fd.rc.Control(func(fd uintptr) {
		optVal, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_SCTP, _SCTP_NODELAY)
	})
	if doErr != nil {
		return false, doErr
	}
	if err != nil {
		return false, os.NewSyscallError("getsockopt", err)
	}
	return intbool(optVal), nil
}

func (fd *sctpFD) setNoDelay(b bool) error {
	if !fd.initialized() {
		return errEINVAL
	}

	var err error
	doErr := fd.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.IPPROTO_SCTP, _SCTP_NODELAY, boolint(b))
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

func (fd *sctpFD) getDisableFragments() (bool, error) {
	if !fd.initialized() {
		return false, errEINVAL
	}

	var err error
	var optVal int
	doErr := fd.rc.Control(func(fd uintptr) {
		optVal, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_SCTP, _SCTP_DISABLE_FRAGMENTS)
	})
	if doErr != nil {
		return false, doErr
	}
	if err != nil {
		return false, os.NewSyscallError("getsockopt", err)
	}
	return intbool(optVal), nil
}

func (fd *sctpFD) setDisableFragments(b bool) error {
	if !fd.initialized() {
		return errEINVAL
	}

	var err error
	doErr := fd.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.IPPROTO_SCTP, _SCTP_DISABLE_FRAGMENTS, boolint(b))
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

func (fd *sctpFD) getMaxseg() (uint32, error) {
	if !fd.initialized() {
		return 0, errEINVAL
	}

	rawParam := assocValue{} // to be filled by the getsockopt call

	var err error
	rawParamBuf := unsafe.Slice((*byte)(unsafe.Pointer(&rawParam)), unsafe.Sizeof(rawParam))
	doErr := fd.rc.Control(func(fd uintptr) {
		err = getsockoptBytes(int(fd), unix.IPPROTO_SCTP, _SCTP_MAXSEG, rawParamBuf)
	})
	if doErr != nil {
		return 0, doErr
	}
	if err != nil {
		log.Printf("gId: %d, getsockopt error: %v, optName: %v, rawParamBuf: %v ", getGoroutineID(), err, _SCTP_MAXSEG, rawParamBuf)
		//debug.PrintStack()
		return 0, os.NewSyscallError("getsockopt", err)
	}
	return rawParam.assocValue, nil
}

func (fd *sctpFD) setMaxseg(maxSeg uint32) error {
	if !fd.initialized() {
		return errEINVAL
	}

	rawParam := assocValue{assocId: 0, assocValue: maxSeg} // to be read by the getsockopt call

	var err error
	rawParamBuf := unsafe.Slice((*byte)(unsafe.Pointer(&rawParam)), unsafe.Sizeof(rawParam))
	doErr := fd.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptString(int(fd), unix.IPPROTO_SCTP, _SCTP_MAXSEG, string(rawParamBuf))
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		log.Printf("gId: %d, sesockopt error: %v, optName: %v, rawParamBuf: %v ", getGoroutineID(), err, _SCTP_MAXSEG, rawParamBuf)
		//debug.PrintStack()
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

func (fd *sctpFD) setSendBuffer(sndBuf int) error {
	if !fd.initialized() {
		return errEINVAL
	}
	var err error
	doErr := fd.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, sndBuf)
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

func (fd *sctpFD) getSendBuffer() (int, error) {
	if !fd.initialized() {
		return 0, errEINVAL
	}
	var err error
	var sndBuf int
	doErr := fd.rc.Control(func(fd uintptr) {
		sndBuf, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	})
	if doErr != nil {
		return 0, doErr
	}
	if err != nil {
		return 0, os.NewSyscallError("getsockopt", err)
	}
	return sndBuf, nil
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

func intbool(i int) bool {
	if i == 0 {
		return false
	}
	return true
}
