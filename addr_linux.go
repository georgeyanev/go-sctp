// Copyright (c) 2024 George Yanev
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

//go:build linux

package sctp

import (
	"encoding/hex"
	"golang.org/x/sys/unix"
	"net"
	"syscall"
	"unsafe"
)

func fromSockaddrBuff(buf []byte, numAddrs int) (*SCTPAddr, error) {
	up := unsafe.Pointer(&buf[0])
	rawSockaddrAny := (*syscall.RawSockaddrAny)(up)

	sctpAddr := SCTPAddr{}

	switch rawSockaddrAny.Addr.Family {
	case syscall.AF_INET:
		rsi4 := (*syscall.RawSockaddrInet4)(up)
		sctpAddr.Port = int(Ntohui16(rsi4.Port))
		for i := 0; i < numAddrs; i++ {
			pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(uintptr(up) + uintptr(i)*unix.SizeofSockaddrInet4))
			sctpAddr.IPAddrs = append(sctpAddr.IPAddrs, net.IPAddr{IP: pp.Addr[:]})
		}

	case syscall.AF_INET6:
		rsi6 := (*syscall.RawSockaddrInet6)(up)
		sctpAddr.Port = int(Ntohui16(rsi6.Port))
		for i := 0; i < numAddrs; i++ {
			pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(uintptr(up) + uintptr(i)*unix.SizeofSockaddrInet6))
			sctpAddr.IPAddrs = append(sctpAddr.IPAddrs, net.IPAddr{IP: pp.Addr[:], Zone: zoneCache.name(int(pp.Scope_id))})
		}

	default:
		return nil, &net.AddrError{Err: "invalid address family", Addr: hex.EncodeToString(buf)}
	}

	return &sctpAddr, nil
}
