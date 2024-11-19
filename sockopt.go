package sctp

import (
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"unsafe"
)

func setInitOpts(fd int, initMsg *InitMsg) error {
	const SCTP_INITMSG = 2
	initMsgBuf := unsafe.Slice((*byte)(unsafe.Pointer(initMsg)), unsafe.Sizeof(*initMsg))
	return os.NewSyscallError("setsockopt", unix.SetsockoptString(int(fd), SOL_SCTP, SCTP_INITMSG, string(initMsgBuf)))
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

func (fd *sctpFD) setNoDelay(b bool) error {
	if !fd.initialized() {
		return errEINVAL
	}

	const SCTP_NODELAY int = 3

	var err error
	doErr := fd.rc.Control(func(fd uintptr) {
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
