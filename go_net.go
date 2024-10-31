// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the GO_LICENSE file.

// This file contains code from go's net package, tweaked for SCTP where necessary.

//go:build linux

package sctp

import (
	"golang.org/x/sys/unix"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Wrapper around the socket system call that marks the returned file
// descriptor as nonblocking and close-on-exec.
func sysSocket(family, sotype, proto int) (int, error) {
	s, err := unix.Socket(family, sotype|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, proto)
	// TODO: We can remove the fallback on Linux and *BSD,
	// as currently supported versions all support accept4
	// with SOCK_CLOEXEC, but Solaris does not. See issue #59359.
	switch err {
	case nil:
		return s, nil
	default:
		return -1, os.NewSyscallError("socket", err)
	case unix.EPROTONOSUPPORT, unix.EINVAL:
	}

	// See ../syscall/exec_unix.go for description of ForkLock.
	syscall.ForkLock.RLock()
	s, err = unix.Socket(family, sotype, proto)
	if err == nil {
		unix.CloseOnExec(s)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return -1, os.NewSyscallError("socket", err)
	}
	if err = unix.SetNonblock(s, true); err != nil {
		_ = unix.Close(s)
		return -1, os.NewSyscallError("setnonblock", err)
	}
	return s, nil
}

// favoriteAddrFamily returns the appropriate address family for the
// given network, laddr, raddr and mode.
//
// If mode indicates "listen" and laddr is a wildcard, we assume that
// the user wants to make a passive-open connection with a wildcard
// address family, both AF_INET and AF_INET6, and a wildcard address
// like the following:
//
//   - A listen for a wildcard communication domain, "sctp",
//     with a wildcard address: If the platform supports
//     both IPv6 and IPv4-mapped IPv6 communication capabilities,
//     or does not support IPv4, we use a dual stack, AF_INET6 and
//     IPV6_V6ONLY=0, wildcard address listen. The dual stack
//     wildcard address listen may fall back to an IPv6-only,
//     AF_INET6 and IPV6_V6ONLY=1, wildcard address listen.
//     Otherwise we prefer an IPv4-only, AF_INET, wildcard address
//     listen.
//
//   - A listen for a wildcard communication domain, "sctp"
//     with an IPv4 wildcard address: same as above.
//
//   - A listen for a wildcard communication domain, "sctp",
//     with an IPv6 wildcard address: same as above.
//
//   - A listen for an IPv4 communication domain, "sctp4",
//     with an IPv4 wildcard address: We use an IPv4-only, AF_INET,
//     wildcard address listen.
//
//   - A listen for an IPv6 communication domain, "sctp6",
//     with an IPv6 wildcard address: We use an IPv6-only, AF_INET6
//     and IPV6_V6ONLY=1, wildcard address listen.
//
// Otherwise guess: If the addresses are IPv4 then returns AF_INET,
// or else returns AF_INET6. It also returns a boolean value what
// designates IPV6_V6ONLY option.
//
// Note that the latest DragonFly BSD and OpenBSD kernels allow
// neither "net.inet6.ip6.v6only=1" change nor IPPROTO_IPV6 level
// IPV6_V6ONLY socket option setting.
// Changes: laddr and raddr parameters are of type *SCTPAddr
func favoriteAddrFamily(network string, laddr, raddr *SCTPAddr, mode string) (family int, ipv6only bool) {
	switch network[len(network)-1] {
	case '4':
		return unix.AF_INET, false
	case '6':
		return unix.AF_INET6, true
	}

	if mode == "listen" && laddr.isWildcard() {
		if supportsIPv4map() || !supportsIPv4() {
			return unix.AF_INET6, false
		}
		if laddr == nil {
			return unix.AF_INET, false
		}
		return laddr.family(), false
	}

	if (laddr == nil || laddr.family() == unix.AF_INET) &&
		(raddr == nil || raddr.family() == unix.AF_INET) {
		return unix.AF_INET, false
	}
	return unix.AF_INET6, false
}

var ipStackCaps ipStackCapabilities

type ipStackCapabilities struct {
	sync.Once             // guards following
	ipv4Enabled           bool
	ipv6Enabled           bool
	ipv4MappedIPv6Enabled bool
}

// supportsIPv4map reports whether the platform supports mapping an
// IPv4 address inside an IPv6 address at transport layer
// protocols. See RFC 4291, RFC 4038 and RFC 3493.
func supportsIPv4map() bool {
	// Some operating systems provide no support for mapping IPv4
	// addresses to IPv6, and a runtime check is unnecessary.
	switch runtime.GOOS {
	case "dragonfly", "openbsd":
		return false
	}

	ipStackCaps.Once.Do(ipStackCaps.probe)
	return ipStackCaps.ipv4MappedIPv6Enabled
}

// supportsIPv4 reports whether the platform supports IPv4 networking
// functionality.
func supportsIPv4() bool {
	ipStackCaps.Once.Do(ipStackCaps.probe)
	return ipStackCaps.ipv4Enabled
}

// supportsIPv6 reports whether the platform supports IPv6 networking
// functionality.
func supportsIPv6() bool {
	ipStackCaps.Once.Do(ipStackCaps.probe)
	return ipStackCaps.ipv6Enabled
}

// probe probes IPv4, IPv6 and IPv4-mapped IPv6 communication
// capabilities which are controlled by the IPV6_V6ONLY socket option
// and kernel configuration.
//
// Should we try to use the IPv4 socket interface if we're only
// dealing with IPv4 sockets? As long as the host system understands
// IPv4-mapped IPv6, it's okay to pass IPv4-mapped IPv6 addresses to
// the IPv6 interface. That simplifies our code and is most
// general. Unfortunately, we need to run on kernels built without
// IPv6 support too. So probe the kernel to figure it out.
func (p *ipStackCapabilities) probe() {
	switch runtime.GOOS {
	case "js", "wasip1":
		// Both ipv4 and ipv6 are faked; see net_fake.go.
		p.ipv4Enabled = true
		p.ipv6Enabled = true
		p.ipv4MappedIPv6Enabled = true
		return
	}

	s, err := sysSocket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	switch err {
	case unix.EAFNOSUPPORT, unix.EPROTONOSUPPORT:
	case nil:
		_ = unix.Close(s)
		p.ipv4Enabled = true
	}
	var probes = []struct {
		laddr net.TCPAddr
		value int
	}{
		// IPv6 communication capability
		{laddr: net.TCPAddr{IP: net.ParseIP("::1")}, value: 1},
		// IPv4-mapped IPv6 address communication capability
		{laddr: net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, value: 0},
	}
	switch runtime.GOOS {
	case "dragonfly", "openbsd":
		// The latest DragonFly BSD and OpenBSD kernels don't
		// support IPV6_V6ONLY=0. They always return an error
		// and we don't need to probe the capability.
		probes = probes[:1]
	}
	for i := range probes {
		s, err := sysSocket(unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP)
		if err != nil {
			continue
		}
		defer func(fd int) {
			_ = unix.Close(fd)
		}(s)
		_ = unix.SetsockoptInt(s, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, probes[i].value)
		sa, err := sockaddr(&(probes[i].laddr), unix.AF_INET6)
		if err != nil {
			continue
		}
		if err := syscall.Bind(s, sa); err != nil {
			continue
		}
		if i == 0 {
			p.ipv6Enabled = true
		} else {
			p.ipv4MappedIPv6Enabled = true
		}
	}
}

func sockaddr(a *net.TCPAddr, family int) (syscall.Sockaddr, error) {
	if a == nil {
		return nil, nil
	}
	return ipToSockaddr(family, a.IP, a.Port, a.Zone)
}

func ipToSockaddr(family int, ip net.IP, port int, zone string) (syscall.Sockaddr, error) {
	switch family {
	case syscall.AF_INET:
		sa, err := ipToSockaddrInet4(ip, port)
		if err != nil {
			return nil, err
		}
		return &sa, nil
	case syscall.AF_INET6:
		sa, err := ipToSockaddrInet6(ip, port, zone)
		if err != nil {
			return nil, err
		}
		return &sa, nil
	}
	return nil, &net.AddrError{Err: "invalid address family", Addr: ip.String()}
}

func ipToSockaddrInet4(ip net.IP, port int) (syscall.SockaddrInet4, error) {
	if len(ip) == 0 {
		ip = net.IPv4zero
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return syscall.SockaddrInet4{}, &net.AddrError{Err: "non-IPv4 address", Addr: ip.String()}
	}
	sa := syscall.SockaddrInet4{Port: port}
	copy(sa.Addr[:], ip4)
	return sa, nil
}

func ipToSockaddrInet6(ip net.IP, port int, zone string) (syscall.SockaddrInet6, error) {
	// In general, an IP wildcard address, which is either
	// "0.0.0.0" or "::", means the entire IP addressing
	// space. For some historical reason, it is used to
	// specify "any available address" on some operations
	// of IP node.
	//
	// When the IP node supports IPv4-mapped IPv6 address,
	// we allow a listener to listen to the wildcard
	// address of both IP addressing spaces by specifying
	// IPv6 wildcard address.
	if len(ip) == 0 || ip.Equal(net.IPv4zero) {
		ip = net.IPv6zero
	}
	// We accept any IPv6 address including IPv4-mapped
	// IPv6 address.
	ip6 := ip.To16()
	if ip6 == nil {
		return syscall.SockaddrInet6{}, &net.AddrError{Err: "non-IPv6 address", Addr: ip.String()}
	}
	// TODO: if this function is used for something other than probing, the zone cache implementation should be pulled here
	sa := syscall.SockaddrInet6{Port: port, ZoneId: uint32(zoneCache.index(zone))}
	copy(sa.Addr[:], ip6)
	return sa, nil
}

// TODO: replace syscall. with unix.
// Change: changed name from sockaddr;
//
//	changed return type
func sockaddrInet4ToBuf(sa4 syscall.SockaddrInet4) ([]byte, error) {
	if sa4.Port < 0 || sa4.Port > 0xFFFF {
		return nil, syscall.EINVAL
	}
	rawSa4 := syscall.RawSockaddrInet4{}
	rawSa4.Family = syscall.AF_INET
	p := (*[2]byte)(unsafe.Pointer(&rawSa4.Port))
	p[0] = byte(sa4.Port >> 8) // works regardless of the host system's endianness
	p[1] = byte(sa4.Port)
	rawSa4.Addr = sa4.Addr // bytes are copied
	return unsafe.Slice((*byte)(unsafe.Pointer(&rawSa4)), syscall.SizeofSockaddrInet4), nil
}

// Change: changed name from sockaddr;
//
//	changed return type
func sockaddrInet6ToBuf(sa6 syscall.SockaddrInet6) ([]byte, error) {
	if sa6.Port < 0 || sa6.Port > 0xFFFF {
		return nil, syscall.EINVAL
	}
	rawSa6 := syscall.RawSockaddrInet6{}
	rawSa6.Family = syscall.AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&rawSa6.Port))
	p[0] = byte(sa6.Port >> 8) // works regardless of the host system's endianness
	p[1] = byte(sa6.Port)
	rawSa6.Scope_id = sa6.ZoneId
	rawSa6.Addr = sa6.Addr // bytes are copied
	return unsafe.Slice((*byte)(unsafe.Pointer(&rawSa6)), syscall.SizeofSockaddrInet6), nil
}

// Changes: set default options for SCTP only
// Note that SCTP is connection-oriented in nature, and it does not support broadcast or multicast
// communications, as UDP does.
func setDefaultSockopts(s, family int, ipv6only bool) error {
	if family == syscall.AF_INET6 {
		// Allow both IP versions even if the OS default
		// is otherwise. Note that some operating systems
		// never admit this option.
		syscall.SetsockoptInt(s, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, boolint(ipv6only))
	}
	return nil
}

// Boolean to int.
func boolint(b bool) int {
	if b {
		return 1
	}
	return 0
}

var listenerBacklogCache struct {
	sync.Once
	val int
}

// listenerBacklog is a caching wrapper around maxListenerBacklog.
func listenerBacklog() int {
	listenerBacklogCache.Do(func() { listenerBacklogCache.val = maxListenerBacklog() })
	return listenerBacklogCache.val
}

// Change: changed implementation not using low level fd functions
func maxListenerBacklog() int {
	data, err := os.ReadFile("/proc/sys/net/core/somaxconn")
	if err != nil {
		return unix.SOMAXCONN
	}
	somaxconnStr := strings.TrimSpace(string(data))
	n, err := strconv.Atoi(somaxconnStr)
	if n <= 0 || err != nil {
		return unix.SOMAXCONN
	}

	if n > 1<<16-1 {
		return maxAckBacklog(n)
	}
	return n
}

// Linux stores the backlog as:
//
//   - uint16 in kernel version < 4.1,
//   - uint32 in kernel version >= 4.1
//
// Truncate number to avoid wrapping.
//
// See issue 5030 and 41470.
func maxAckBacklog(n int) int {
	major, minor := KernelVersion()
	size := 16
	if major > 4 || (major == 4 && minor >= 1) {
		size = 32
	}

	var maxUint uint = 1<<size - 1
	if uint(n) > maxUint {
		n = int(maxUint)
	}
	return n
}

// KernelVersion returns major and minor kernel version numbers, parsed from
// the unix.Uname's Release field, or 0, 0 if the version can't be obtained
// or parsed.
//
// Currently only implemented for Linux.
func KernelVersion() (major, minor int) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return
	}

	var (
		values    [2]int
		value, vi int
	)
	for _, c := range uname.Release {
		if '0' <= c && c <= '9' {
			value = (value * 10) + int(c-'0')
		} else {
			// Note that we're assuming N.N.N here.
			// If we see anything else, we are likely to mis-parse it.
			values[vi] = value
			vi++
			if vi >= len(values) {
				break
			}
			value = 0
		}
	}

	return values[0], values[1]
}

// Bigger than we need, not too big to worry about overflow
const big = 0xFFFFFF

// Decimal to integer.
// Returns number, characters consumed, success.
func dtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= big {
			return big, i, false
		}
	}
	if i == 0 {
		return 0, 0, false
	}
	return n, i, true
}

// uitoa converts val to a decimal string.
func uitoa(val uint) string {
	if val == 0 { // avoid string allocation
		return "0"
	}
	var buf [20]byte // big enough for 64bit value base 10
	i := len(buf) - 1
	for val >= 10 {
		q := val / 10
		buf[i] = byte('0' + val - q*10)
		i--
		val = q
	}
	// val < 10
	buf[i] = byte('0' + val)
	return string(buf[i:])
}

// An ipv6ZoneCache represents a cache holding partial network
// interface information. It is used for reducing the cost of IPv6
// addressing scope zone resolution.
//
// Multiple names sharing the index are managed by first-come
// first-served basis for consistency.
type ipv6ZoneCache struct {
	sync.RWMutex                // guard the following
	lastFetched  time.Time      // last time routing information was fetched
	toIndex      map[string]int // interface name to its index
	toName       map[int]string // interface index to its name
}

var zoneCache = ipv6ZoneCache{
	toIndex: make(map[string]int),
	toName:  make(map[int]string),
}

func (zc *ipv6ZoneCache) index(name string) int {
	if name == "" {
		return 0
	}
	updated := zoneCache.update(nil, false)
	zoneCache.RLock()
	index, ok := zoneCache.toIndex[name]
	zoneCache.RUnlock()
	if !ok && !updated {
		zoneCache.update(nil, true)
		zoneCache.RLock()
		index, ok = zoneCache.toIndex[name]
		zoneCache.RUnlock()
	}
	if !ok { // last resort
		index, _, _ = dtoi(name)
	}
	return index
}

// update refreshes the network interface information if the cache was last
// updated more than 1 minute ago, or if force is set. It reports whether the
// cache was updated.
func (zc *ipv6ZoneCache) update(ift []net.Interface, force bool) (updated bool) {
	zc.Lock()
	defer zc.Unlock()
	now := time.Now()
	if !force && zc.lastFetched.After(now.Add(-60*time.Second)) {
		return false
	}
	zc.lastFetched = now
	if len(ift) == 0 {
		var err error
		if ift, err = interfaceTable(0); err != nil {
			return false
		}
	}
	zc.toIndex = make(map[string]int, len(ift))
	zc.toName = make(map[int]string, len(ift))
	for _, ifi := range ift {
		zc.toIndex[ifi.Name] = ifi.Index
		if _, ok := zc.toName[ifi.Index]; !ok {
			zc.toName[ifi.Index] = ifi.Name
		}
	}
	return true
}

func (zc *ipv6ZoneCache) name(index int) string {
	if index == 0 {
		return ""
	}
	updated := zoneCache.update(nil, false)
	zoneCache.RLock()
	name, ok := zoneCache.toName[index]
	zoneCache.RUnlock()
	if !ok && !updated {
		zoneCache.update(nil, true)
		zoneCache.RLock()
		name, ok = zoneCache.toName[index]
		zoneCache.RUnlock()
	}
	if !ok { // last resort
		name = uitoa(uint(index))
	}
	return name
}

// If the ifindex is zero, interfaceTable returns mappings of all
// network interfaces. Otherwise it returns a mapping of a specific
// interface.
func interfaceTable(ifindex int) ([]net.Interface, error) {
	tab, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return nil, os.NewSyscallError("netlinkrib", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, os.NewSyscallError("parsenetlinkmessage", err)
	}
	var ift []net.Interface
loop:
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			break loop
		case syscall.RTM_NEWLINK:
			ifim := (*syscall.IfInfomsg)(unsafe.Pointer(&m.Data[0]))
			if ifindex == 0 || ifindex == int(ifim.Index) {
				attrs, err := syscall.ParseNetlinkRouteAttr(&m)
				if err != nil {
					return nil, os.NewSyscallError("parsenetlinkrouteattr", err)
				}
				ift = append(ift, *newLink(ifim, attrs))
				if ifindex == int(ifim.Index) {
					break loop
				}
			}
		}
	}
	return ift, nil
}

const (
	// See linux/if_arp.h.
	// Note that Linux doesn't support IPv4 over IPv6 tunneling.
	sysARPHardwareIPv4IPv4 = 768 // IPv4 over IPv4 tunneling
	sysARPHardwareIPv6IPv6 = 769 // IPv6 over IPv6 tunneling
	sysARPHardwareIPv6IPv4 = 776 // IPv6 over IPv4 tunneling
	sysARPHardwareGREIPv4  = 778 // any over GRE over IPv4 tunneling
	sysARPHardwareGREIPv6  = 823 // any over GRE over IPv6 tunneling
)

func newLink(ifim *syscall.IfInfomsg, attrs []syscall.NetlinkRouteAttr) *net.Interface {
	ifi := &net.Interface{Index: int(ifim.Index), Flags: linkFlags(ifim.Flags)}
	for _, a := range attrs {
		switch a.Attr.Type {
		case syscall.IFLA_ADDRESS:
			// We never return any /32 or /128 IP address
			// prefix on any IP tunnel interface as the
			// hardware address.
			switch len(a.Value) {
			case net.IPv4len:
				switch ifim.Type {
				case sysARPHardwareIPv4IPv4, sysARPHardwareGREIPv4, sysARPHardwareIPv6IPv4:
					continue
				}
			case net.IPv6len:
				switch ifim.Type {
				case sysARPHardwareIPv6IPv6, sysARPHardwareGREIPv6:
					continue
				}
			}
			var nonzero bool
			for _, b := range a.Value {
				if b != 0 {
					nonzero = true
					break
				}
			}
			if nonzero {
				ifi.HardwareAddr = a.Value[:]
			}
		case syscall.IFLA_IFNAME:
			ifi.Name = string(a.Value[:len(a.Value)-1])
		case syscall.IFLA_MTU:
			ifi.MTU = int(*(*uint32)(unsafe.Pointer(&a.Value[:4][0])))
		}
	}
	return ifi
}

func linkFlags(rawFlags uint32) net.Flags {
	var f net.Flags
	if rawFlags&syscall.IFF_UP != 0 {
		f |= net.FlagUp
	}
	if rawFlags&syscall.IFF_RUNNING != 0 {
		f |= net.FlagRunning
	}
	if rawFlags&syscall.IFF_BROADCAST != 0 {
		f |= net.FlagBroadcast
	}
	if rawFlags&syscall.IFF_LOOPBACK != 0 {
		f |= net.FlagLoopback
	}
	if rawFlags&syscall.IFF_POINTOPOINT != 0 {
		f |= net.FlagPointToPoint
	}
	if rawFlags&syscall.IFF_MULTICAST != 0 {
		f |= net.FlagMulticast
	}
	return f
}

// Do the interface allocations only once for common
// Errno values.
var (
	errEAGAIN error = unix.EAGAIN
	errEINVAL error = unix.EINVAL
	errENOENT error = unix.ENOENT
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case unix.EAGAIN:
		return errEAGAIN
	case unix.EINVAL:
		return errEINVAL
	case unix.ENOENT:
		return errENOENT
	}
	return e
}