package sctp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"strconv"
	"strings"
	"unsafe"
)

// SCTPAddr represents the address of a SCTP endpoint. It contains an address array
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

	var b bytes.Buffer
	for n, i := range a.IPAddrs {
		if i.IP.To4() != nil {
			b.WriteString(i.String())
		} else if i.IP.To16() != nil {
			b.WriteRune('[')
			b.WriteString(i.String())
			b.WriteRune(']')
		}
		if n < len(a.IPAddrs)-1 {
			b.WriteRune('/')
		}
	}
	b.WriteRune(':')
	b.WriteString(strconv.Itoa(a.Port))
	return b.String()
}

// Wildcard addresses cannot be used in combination with non-wildcard addresses.
// A single address may be specified as a wildcard address.
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
		return unix.AF_INET
	}
	for _, ip := range a.IPAddrs {
		if ip.IP.To4() == nil {
			return unix.AF_INET6
		}
	}
	return unix.AF_INET
}

func (a *SCTPAddr) matchAddrFamily(x *SCTPAddr) bool {
	return a.family() == unix.AF_INET && x.family() == unix.AF_INET ||
		a.family() == unix.AF_INET6 && x.family() == unix.AF_INET6
}

func (a *SCTPAddr) opAddr() net.Addr {
	if a == nil {
		return nil
	}
	return a
}

func (a *SCTPAddr) toSockaddrBuff(family int) ([]byte, error) {
	var port int = 0
	if a != nil {
		port = a.Port
	}
	var buf []byte
	switch {
	case family == unix.AF_INET && a.isEmpty():
		sa, err := ipToSockaddrInet4(nil, port)
		if err != nil {
			return nil, err
		}
		saBuf, err := sockaddrInet4ToBuf(sa)
		if err != nil {
			return nil, err
		}
		buf = append(buf, saBuf...)

	case family == unix.AF_INET6 && a.isEmpty():
		sa, err := ipToSockaddrInet6(nil, port, "")
		if err != nil {
			return nil, err
		}
		saBuf, err := sockaddrInet6ToBuf(sa)
		if err != nil {
			return nil, err
		}
		buf = append(buf, saBuf...)

	case family == unix.AF_INET:
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
	case family == unix.AF_INET6:
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
		return nil, &net.AddrError{Err: fmt.Sprintf("invalid address family: %d", family), Addr: a.String()}
	}

	return buf, nil
}

func resolveSCTPAddr(op, network, addr string, hint *SCTPAddr) (*SCTPAddr, error) {
	switch network {
	case "sctp", "sctp4", "sctp6":
	default:
		return nil, net.UnknownNetworkError(network)
	}
	addr = strings.TrimSpace(addr)
	if op == "dial" && addr == "" {
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
	// last address contains the port number so use TCP resolver
	tcpAddr, err := net.ResolveTCPAddr(strings.ReplaceAll(network, "sctp", "tcp"), addrs[len(addrs)-1])
	if err != nil {
		return nil, err
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

func fromSockaddrBuff(buf []byte, numAddrs int) (*SCTPAddr, error) {
	up := unsafe.Pointer(&buf[0])
	rawSockaddrAny := (*unix.RawSockaddrAny)(up)

	sctpAddr := SCTPAddr{}

	switch rawSockaddrAny.Addr.Family {
	case unix.AF_INET:
		rsi4 := (*unix.RawSockaddrInet4)(up)
		p := (*[2]byte)(unsafe.Pointer(&rsi4.Port))
		sctpAddr.Port = int(p[0])<<8 + int(p[1]) // works regardless of the host system's endianness
		for i := 0; i < numAddrs; i++ {
			pp := (*unix.RawSockaddrInet4)(unsafe.Pointer(uintptr(up) + uintptr(i)*unix.SizeofSockaddrInet4))
			sctpAddr.IPAddrs = append(sctpAddr.IPAddrs, net.IPAddr{IP: pp.Addr[:]})
		}

	case unix.AF_INET6:
		rsi6 := (*unix.RawSockaddrInet6)(up)
		p := (*[2]byte)(unsafe.Pointer(&rsi6.Port))
		sctpAddr.Port = int(p[0])<<8 + int(p[1])
		for i := 0; i < numAddrs; i++ {
			pp := (*unix.RawSockaddrInet6)(unsafe.Pointer(uintptr(up) + uintptr(i)*unix.SizeofSockaddrInet6))
			sctpAddr.IPAddrs = append(sctpAddr.IPAddrs, net.IPAddr{IP: pp.Addr[:], Zone: zoneCache.name(int(pp.Scope_id))})
		}

	default:
		return nil, &net.AddrError{Err: "invalid address family", Addr: hex.EncodeToString(buf)}
	}

	return &sctpAddr, nil
}
