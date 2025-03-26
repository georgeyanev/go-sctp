// Copyright (c) 2024 George Yanev
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

//go:build linux

package sctp

import (
	"golang.org/x/sys/unix"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
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
	err = unix.SetsockoptInt(fd, syscall.SOL_SOCKET, unix.SO_RCVBUFFORCE, initOptions.SocketReadBufferSize)
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

	// set adaptation layer indication
	if initOptions.AdaptationIndicationEnabled {
		const SCTP_ADAPTATION_LAYER = 7
		type setAdaptation struct {
			adaptationInd uint32
		}
		sa := setAdaptation{
			adaptationInd: initOptions.AdaptationIndication,
		}
		saBuf := unsafe.Slice((*byte)(unsafe.Pointer(&sa)), unsafe.Sizeof(sa))
		if err = unix.SetsockoptString(fd, unix.IPPROTO_SCTP, SCTP_ADAPTATION_LAYER, string(saBuf)); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	}
	return nil
}

func (fd *sctpFD) retrieveAddr(optName int) (*SCTPAddr, error) {
	if !fd.initialized() {
		return nil, unix.EINVAL
	}

	// SCTP_ADDRS_BUF_SIZE is the allocated buffer for system calls returning local/remote sctp multi-homed addresses
	const SCTP_ADDRS_BUF_SIZE int = 4096 //enough for most cases

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
		return nil, os.NewSyscallError("getsockopt", err)
	}

	sctpAddr, err := fromSockaddrBuff(rawParam.addrs[:], int(rawParam.addrNum))
	if err != nil {
		return nil, err
	}

	return sctpAddr, nil
}

func (fd *sctpFD) subscribe(event EventType, enabled bool) error {
	if !fd.initialized() {
		return unix.EINVAL
	}
	const SCTP_EVENT = 127
	type sctpEventType struct {
		_      int32
		seType uint16
		seOn   uint8
	}

	sctpEvent := sctpEventType{seType: uint16(event), seOn: uint8(boolint(enabled))}
	sctpEventBuf := unsafe.Slice((*byte)(unsafe.Pointer(&sctpEvent)), unsafe.Sizeof(sctpEvent))

	var err error
	doErr := fd.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptString(int(fd), unix.IPPROTO_SCTP, SCTP_EVENT, string(sctpEventBuf))
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

func (fd *sctpFD) setNoDelay(b bool) error {
	if !fd.initialized() {
		return unix.EINVAL
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

func (fd *sctpFD) setDisableFragments(b bool) error {
	if !fd.initialized() {
		return unix.EINVAL
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

func (fd *sctpFD) writeBufferSize() (int, error) {
	if !fd.initialized() {
		return 0, unix.EINVAL
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

func (fd *sctpFD) readBufferSize() (int, error) {
	if !fd.initialized() {
		return 0, unix.EINVAL
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

func (fd *sctpFD) setLinger(sec int) error {
	if !fd.initialized() {
		return unix.EINVAL
	}
	var l unix.Linger
	if sec >= 0 {
		l.Onoff = 1
		l.Linger = int32(sec)
	} else {
		l.Onoff = 0
		l.Linger = 0
	}

	var err error
	doErr := fd.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptLinger(int(fd), unix.SOL_SOCKET, unix.SO_LINGER, &l)
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

// TODO: Add parameter for setting the remote address (if different than the primary)
func (fd *sctpFD) status() (*Status, error) {
	if !fd.initialized() {
		return nil, unix.EINVAL
	}
	const SCTP_STATUS int = 14
	type peerAddrInfo struct {
		assocId int32
		addr    [128]byte // sizeof(sockaddr_storage)
		state   int32
		cwnd    uint32
		srtt    uint32
		rto     uint32
		mtu     uint32
	}
	type sctpStatus struct {
		assocId            int32
		state              int32
		rwnd               uint32
		unackData          uint16
		pendingData        uint16
		inStreams          uint16
		outStreams         uint16
		fragmentationPoint uint32
		primaryAddrInfo    peerAddrInfo
	}
	rawParam := sctpStatus{} // to be filled by the getsockopt call

	var err error
	rawParamBuf := unsafe.Slice((*byte)(unsafe.Pointer(&rawParam)), unsafe.Sizeof(rawParam))
	doErr := fd.rc.Control(func(fd uintptr) {
		err = getsockoptBytes(int(fd), unix.IPPROTO_SCTP, SCTP_STATUS, rawParamBuf)
	})
	if doErr != nil {
		return nil, doErr
	}
	if err != nil {
		return nil, os.NewSyscallError("getsockopt", err)
	}

	sctpAddr, err := fromSockaddrBuff(rawParam.primaryAddrInfo.addr[:], 1)
	if err != nil {
		return nil, err
	}

	return &Status{
		AssocId:            rawParam.assocId,
		State:              rawParam.state,
		Rwnd:               rawParam.rwnd,
		UnackData:          rawParam.unackData,
		PendingData:        rawParam.pendingData,
		InStreams:          rawParam.inStreams,
		OutStreams:         rawParam.outStreams,
		FragmentationPoint: rawParam.fragmentationPoint,
		PrimaryAddrInfo: &PeerAddrInfo{
			AssocId: rawParam.primaryAddrInfo.assocId,
			Addr:    sctpAddr,
			State:   rawParam.primaryAddrInfo.state,
			Cwnd:    rawParam.primaryAddrInfo.cwnd,
			Srtt:    rawParam.primaryAddrInfo.srtt,
			Rto:     rawParam.primaryAddrInfo.rto,
			Mtu:     rawParam.primaryAddrInfo.mtu,
		},
	}, nil
}

func (fd *sctpFD) setHeartbeat(d time.Duration, to *net.IPAddr) error {
	if !fd.initialized() {
		return unix.EINVAL
	}
	const SCTP_PEER_ADDR_PARAMS int = 9
	type peerAddrParams struct {
		// the C padding of sctp_paddrparams is different from the Go padding (156 vs 160 bytes),
		// in which case we allocate the buffer with the C's size and deal with the fields manually (see below)
		data [156]byte
	}

	var toSctpAddr *SCTPAddr = nil
	if to != nil {
		toSctpAddr = &SCTPAddr{
			IPAddrs: []net.IPAddr{*to},
			Port:    fd.raddr.Load().Port,
		}
	}

	var err error
	toAddrBuf, err := toSctpAddr.toSockaddrBuff(fd.family)
	if err != nil {
		return &net.AddrError{Err: err.Error(), Addr: toSctpAddr.String()}
	}
	params := peerAddrParams{}
	copy(params.data[4:132], toAddrBuf) // sets the to address

	// first get the current params
	doErr := fd.rc.Control(func(fd uintptr) {
		err = getsockoptBytes(int(fd), unix.IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, params.data[:])
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return os.NewSyscallError("getsockopt", err)
	}

	// get current flags
	hbInterval := *(*uint32)(unsafe.Pointer(&params.data[132]))
	flags := *(*uint32)(unsafe.Pointer(&params.data[146]))

	// now change hb-interval and flags accordingly
	var millis uint32
	if d == 0 {
		millis = hbInterval
	}
	if d > 0 {
		millis = uint32(roundDurationUp(d, time.Millisecond))
	}
	const SPP_HB_ENABLE = 1
	const SPP_HB_DISABLE = 2
	if d < 0 { // disable heartbeat
		flags &^= SPP_HB_ENABLE
		flags |= SPP_HB_DISABLE
	} else { // enable heartbeat
		flags |= SPP_HB_ENABLE
		flags &^= SPP_HB_DISABLE
	}
	*(*uint32)(unsafe.Pointer(&params.data[132])) = millis // hb-interval
	*(*uint32)(unsafe.Pointer(&params.data[146])) = flags  // flags

	// set the new params
	doErr = fd.rc.Control(func(fd uintptr) {
		err = unix.SetsockoptString(int(fd), unix.IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, string(params.data[:]))
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}

	return nil
	/*
		// Setting values
		*(*int32)(unsafe.Pointer(&params.data[0])) = 42 // assocId
		copy(params.data[4:132], make([]byte, 128))    // addr
		*(*uint32)(unsafe.Pointer(&params.data[132])) = 1000 // hbInterval
		*(*uint16)(unsafe.Pointer(&params.data[136])) = 5    // pathMaxRxt
		*(*uint32)(unsafe.Pointer(&params.data[138])) = 1500 // pathMtu
		*(*uint32)(unsafe.Pointer(&params.data[142])) = 200  // sackDelay
		*(*uint32)(unsafe.Pointer(&params.data[146])) = 1    // flags
		*(*uint32)(unsafe.Pointer(&params.data[150])) = 20   // ipv6FlowLabel
		params.data[154] = 10                                // dscp

		// Access and print the values to verify
		assocId := int32(*(*uint32)(unsafe.Pointer(&params.data[0])))
		addr := (*[128]byte)(unsafe.Pointer(&params.data[4]))
		hbInterval := uint32(*(*uint32)(unsafe.Pointer(&params.data[132])))
		pathMaxRxt := uint16(*(*uint16)(unsafe.Pointer(&params.data[136])))
		pathMtu := uint32(*(*uint32)(unsafe.Pointer(&params.data[138])))
		sackDelay := uint32(*(*uint32)(unsafe.Pointer(&params.data[142])))
		flags := uint32(*(*uint32)(unsafe.Pointer(&params.data[146])))
		ipv6FlowLabel := uint32(*(*uint32)(unsafe.Pointer(&params.data[150])))
		dscp := uint8(*(*uint8)(unsafe.Pointer(&params.data[154])))

		fmt.Println("Size of struct:", unsafe.Sizeof(params)) // Should output 156
		fmt.Printf("AssocId: %v, Addr: %v, HBInterval: %v, PathMaxRxt: %v, PathMTU: %v, SackDelay: %v, Flags: %v, IPv6FlowLabel: %v, DSCP: %v\n",
			assocId, addr, hbInterval, pathMaxRxt, pathMtu, sackDelay, flags, ipv6FlowLabel, dscp)
	*/
}

func getsockoptBytes(fd, level, opt int, b []byte) error {
	p := unsafe.Pointer(&b[0])
	vallen := uint32(len(b))

	switch runtime.GOARCH {
	case "s390x", "386":
		const (
			SYS_SOCKETCALL = 102
			_GETSOCKOPT    = 15
		)
		args := [5]uintptr{uintptr(fd), uintptr(level), uintptr(opt), uintptr(p), uintptr(unsafe.Pointer(&vallen))}
		_, _, err := unix.Syscall(SYS_SOCKETCALL, _GETSOCKOPT, uintptr(unsafe.Pointer(&args)), 0)
		if err != 0 {
			return err
		}
		return nil
	}
	_, _, err := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt), uintptr(p), uintptr(unsafe.Pointer(&vallen)), 0)
	if err != 0 {
		return err
	}
	return nil
}
