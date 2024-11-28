package sctp

import (
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"unsafe"
)

const (
	_SCTP_NODELAY           = 3
	_SCTP_DISABLE_FRAGMENTS = 8
	_SCTP_SOCKOPT_BINDX_ADD = 100
	_SCTP_SOCKOPT_BINDX_REM = 101
)

func setInitOptions(fd int, initOptions InitOptions) error {
	const SCTP_INITMSG = 2
	type InitMsg struct {
		NumOstreams    uint16
		MaxInstreams   uint16
		MaxAttempts    uint16
		MaxInitTimeout uint16
	}

	// set default values
	if initOptions.NumOstreams == 0 {
		initOptions.NumOstreams = 10
	}
	if initOptions.MaxInstreams == 0 {
		initOptions.MaxInstreams = 10
	}
	if initOptions.SocketReadBufferSize == 0 {
		initOptions.SocketReadBufferSize = 512 * 1024
	}
	if initOptions.SocketWriteBufferSize == 0 {
		initOptions.SocketWriteBufferSize = 512 * 1024
	}

	initMsg := InitMsg{
		NumOstreams:    initOptions.NumOstreams,
		MaxInstreams:   initOptions.MaxInstreams,
		MaxAttempts:    initOptions.MaxAttempts,
		MaxInitTimeout: initOptions.MaxInitTimeout,
	}

	// initMsg
	initMsgBuf := unsafe.Slice((*byte)(unsafe.Pointer(&initMsg)), unsafe.Sizeof(initMsg))
	err := unix.SetsockoptString(fd, unix.IPPROTO_SCTP, SCTP_INITMSG, string(initMsgBuf))
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}

	// In some environments (like Docker Desktop linuxkit), we don't have access to certain kernel
	// parameters, so first we try to set the buffers forcefully.
	// read socket buffer
	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, initOptions.SocketReadBufferSize)
	if err != nil {
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, initOptions.SocketReadBufferSize); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	}

	// write socket buffer
	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, initOptions.SocketWriteBufferSize)
	if err != nil {
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, initOptions.SocketWriteBufferSize); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	}

	// set option to receive RcvInfo
	const SCTP_RECVRCVINFO = 32
	if err = unix.SetsockoptInt(fd, unix.IPPROTO_SCTP, SCTP_RECVRCVINFO, 1); err != nil {
		return err
	}

	return nil
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

func (fd *sctpFD) getWriteBuffer() (int, error) {
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

func (fd *sctpFD) getReadBuffer() (int, error) {
	if !fd.initialized() {
		return 0, errEINVAL
	}
	var err error
	var sndBuf int
	doErr := fd.rc.Control(func(fd uintptr) {
		sndBuf, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
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
