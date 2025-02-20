// Copyright (c) 2024 George Yanev
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sctp

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
)

// SCTPAddr represents the address of an SCTP endpoint. It contains an address array
// because of the multi-homing feature of SCTP
type SCTPAddr struct {
	IPAddrs []net.IPAddr
	Port    int
}

func (a *SCTPAddr) Network() string { return "sctp" }

func (a *SCTPAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	var ipStrings []string
	for _, ipAddr := range a.IPAddrs {
		if ipAddr.IP.To4() != nil {
			ipStrings = append(ipStrings, ipAddr.String())
		} else if ipAddr.IP.To16() != nil {
			ipStrings = append(ipStrings, "["+ipAddr.String()+"]")
		}
	}
	return strings.Join(ipStrings, "/") + fmt.Sprintf(":%d", a.Port)
}

// Wildcard addresses cannot be used in combination with non-wildcard addresses.
// A single net.IPAddr address may be specified as a wildcard address.
func (a *SCTPAddr) isWildcard() bool {
	if a.isEmpty() {
		return true
	}
	if len(a.IPAddrs) > 1 {
		return false
	}
	return a.IPAddrs[0].IP.IsUnspecified()
}

func (a *SCTPAddr) isEmpty() bool {
	if a == nil || len(a.IPAddrs) == 0 || (len(a.IPAddrs) == 1 && len(a.IPAddrs[0].IP) == 0) {
		return true
	}
	return false
}

func (a *SCTPAddr) family() int {
	if a == nil || len(a.IPAddrs) == 0 || len(a.IPAddrs[0].IP) <= net.IPv4len {
		return syscall.AF_INET
	}
	for _, ip := range a.IPAddrs {
		if ip.IP.To4() == nil {
			return syscall.AF_INET6
		}
	}
	return syscall.AF_INET
}

func (a *SCTPAddr) matchAddrFamily(x *SCTPAddr) bool {
	return a.family() == syscall.AF_INET && x.family() == syscall.AF_INET ||
		a.family() == syscall.AF_INET6 && x.family() == syscall.AF_INET6
}

func (a *SCTPAddr) opAddr() net.Addr {
	if a == nil {
		return nil
	}
	return a
}

func (a *SCTPAddr) toSockaddrBuff(family int) ([]byte, error) {
	var port = 0
	if a != nil {
		port = a.Port
	}
	var buf []byte
	switch {
	case family == syscall.AF_INET && a.isEmpty():
		sa, err := ipToSockaddrInet4(nil, port)
		if err != nil {
			return nil, err
		}
		saBuf, err := sockaddrInet4ToBuf(sa)
		if err != nil {
			return nil, err
		}
		buf = append(buf, saBuf...)

	case family == syscall.AF_INET6 && a.isEmpty():
		sa, err := ipToSockaddrInet6(nil, port, "")
		if err != nil {
			return nil, err
		}
		saBuf, err := sockaddrInet6ToBuf(sa)
		if err != nil {
			return nil, err
		}
		buf = append(buf, saBuf...)

	case family == syscall.AF_INET:
		for _, ip := range a.IPAddrs {
			sa, err := ipToSockaddrInet4(ip.IP, port)
			if err != nil {
				return nil, err
			}
			saBuf, err := sockaddrInet4ToBuf(sa)
			if err != nil {
				return nil, err
			}
			buf = append(buf, saBuf...)
		}
	case family == syscall.AF_INET6:
		for _, ip := range a.IPAddrs {
			sa, err := ipToSockaddrInet6(ip.IP, port, ip.Zone)
			if err != nil {
				return nil, err
			}
			saBuf, err := sockaddrInet6ToBuf(sa)
			if err != nil {
				return nil, err
			}
			buf = append(buf, saBuf...)
		}
	default:
		return nil, fmt.Errorf("invalid address family: %d", family)
	}

	return buf, nil
}

// ResolveSCTPAddr returns an address of an SCTP end point.
// The network must be an SCTP network name.
// See func [Dial] for a description of the network and address parameters.
func ResolveSCTPAddr(network, addr string) (*SCTPAddr, error) {
	return resolveSCTPAddr("resolve", network, addr, nil)
}

func resolveSCTPAddr(op, network, addr string, hint *SCTPAddr) (*SCTPAddr, error) {
	switch network {
	case "sctp", "sctp4", "sctp6":
	default:
		return nil, net.UnknownNetworkError(network)
	}
	addr = strings.TrimSpace(addr)
	if (op == "dial" || op == "bindx") && addr == "" {
		return nil, errors.New("missing address")
	}
	if addr == "" {
		return nil, nil
	}
	addrs := strings.Split(addr, "/")
	if len(addrs) == 0 {
		return nil, &net.AddrError{Err: "invalid address", Addr: addr}
	}
	var ipAddrs []net.IPAddr
	for _, oneAddr := range addrs[:len(addrs)-1] { // process all except the last
		ipAddr, err := net.ResolveIPAddr(
			strings.ReplaceAll(network, "sctp", "ip"),
			strings.Trim(oneAddr, "[]")) // omit [] boundaries from ipv6 addresses
		if err != nil {
			return nil, err
		}
		ipAddrs = append(ipAddrs, *ipAddr)
	}

	// process last address
	var tcpAddr *net.TCPAddr
	var err error
	if op == "bindx" { // address does not contain port number so use IP resolver
		ipAddr, err := net.ResolveIPAddr(
			strings.ReplaceAll(network, "sctp", "ip"),
			strings.Trim(addrs[len(addrs)-1], "[]")) // omit [] boundaries from ipv6 addresses
		if err != nil {
			return nil, err
		}
		tcpAddr = &net.TCPAddr{IP: ipAddr.IP, Zone: ipAddr.Zone}
	} else { // last address contains the port number so use TCP resolver
		tcpAddr, err = net.ResolveTCPAddr(strings.ReplaceAll(network, "sctp", "tcp"), addrs[len(addrs)-1])
		if err != nil {
			return nil, err
		}
	}
	if op == "dial" && tcpAddr.Port == 0 {
		return nil, &net.AddrError{Err: "missing port in address", Addr: addr}
	}

	ipAddrs = append(ipAddrs, net.IPAddr{IP: tcpAddr.IP, Zone: tcpAddr.Zone})

	resAddr := &SCTPAddr{IPAddrs: ipAddrs, Port: tcpAddr.Port}
	if op != "dial" || hint == nil {
		return resAddr, err
	}

	if !hint.isWildcard() && !resAddr.isWildcard() && !hint.matchAddrFamily(resAddr) {
		return nil, &net.AddrError{Err: errNoSuitableAddress.Error(), Addr: hint.String()}
	}

	return &SCTPAddr{IPAddrs: ipAddrs, Port: tcpAddr.Port}, nil
}
