package sctp

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"strings"
	"syscall"
	"testing"
)

var sctpListenerTests = []struct {
	network string
	address string
}{

	{"sctp4", "127.0.0.1"},
	{"sctp4", "[::ffff:127.0.0.1]"},
	{"sctp4", ""},
	{"sctp4", "0.0.0.0"},
	{"sctp4", "[::ffff:0.0.0.0]"},
	{"sctp4", "127.0.0.1/127.0.0.2/127.0.0.3"},
	{"sctp4", "[::ffff:127.0.0.1]/[::ffff:127.0.0.2]/[::ffff:127.0.0.3]"},
	{"sctp4", "[::ffff:127.0.0.1]/127.0.0.2/[::ffff:127.0.0.3]"},
	{"sctp6", "[::1]"},
	{"sctp6", ""},
	{"sctp6", "[::1%lo]"},
	{"sctp6", "[::1%nazone]"},
	{"sctp6", "[::]"},
	{"sctp6", "[::1]"},
	//{"sctp6", "[::1]/[fe80::1%lo]/[fe80::2%lo]"}, // additional addresses needed
	{"sctp", "0.0.0.0"},
	{"sctp", ""},
	{"sctp", "[::ffff:0.0.0.0]"},
	{"sctp", "[::]"},
	{"sctp", "127.0.0.1"},
	{"sctp", "[::ffff:127.0.0.1]"},
	{"sctp", "[::1]"},
	{"sctp", "[::1]/127.0.0.1/[::ffff:127.0.0.3]"},
}

var sctpListenerNilAddressTests = []struct {
	network string
	address string
}{
	{"sctp4", ""},
	{"sctp4", ":"},
	{"sctp4", "127.0.0.1:"},
	{"sctp6", ""},
	{"sctp6", ":"},
	{"sctp6", "[::1]:"},
	{"sctp", ""},
	{"sctp", ":"},
	{"sctp", "127.0.0.1:"},
	{"sctp", "[::1]:"},
}

// TestTCPListener tests both single and double listen to a test
// listener with same address family, same listening address and
// same port.
func TestSCTPListener(t *testing.T) {
	for _, tt := range sctpListenerTests {
		ln1, err := Listen(tt.network, tt.address+":0")
		if err != nil {
			t.Fatal(err)
		}
		if err := checkFirstListener(tt.network, ln1); err != nil {
			_ = ln1.Close()
			t.Fatal(err)
		}
		fmt.Println("ln1 address: ", ln1.Addr())
		// listen on the same port from a second listener should fail
		ln2, err := Listen(tt.network, tt.address+":"+ln1.(*SCTPListener).port())
		if err == nil {
			_ = ln2.Close()
		}
		if err := checkSecondListener(tt.network, tt.address, err); err != nil {
			_ = ln1.Close()
			t.Fatal(err)
		}
		_ = ln1.Close()
	}
}

func TestSCTPListenerNoPortAdded(t *testing.T) {
	// test empty addresses without adding port number
	for _, tt := range sctpListenerNilAddressTests {
		ln1, err := Listen(tt.network, tt.address)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkFirstListener(tt.network, ln1); err != nil {
			_ = ln1.Close()
			t.Fatal(err)
		}
		ln2, err := Listen(tt.network, tt.address+":"+ln1.(*SCTPListener).port())
		fmt.Println("ln1 address: ", ln1.Addr())
		if err == nil {
			_ = ln2.Close()
		}
		if err := checkSecondListener(tt.network, tt.address, err); err != nil {
			_ = ln1.Close()
			t.Fatal(err)
		}
		_ = ln1.Close()
	}
}

var dualStackSCTPListenerTests = []struct {
	network1, address1 string // first listener
	network2, address2 string // second listener
	xerr               error  // expected error value, nil or other
}{
	// Test cases and expected results for the attempting 2nd listen on the same port
	// 1st listen                2nd listen                 linux
	// -----------------------------------------------------------
	// "sctp"  ""                 "sctp"  ""                    -
	// "sctp"  ""                 "sctp"  "0.0.0.0"             -
	// "sctp"  "0.0.0.0"          "sctp"  ""                    -
	// -----------------------------------------------------------
	// "sctp"  ""                 "sctp"  "[::]"                -
	// "sctp"  "[::]"             "sctp"  ""                    -
	// "sctp"  "0.0.0.0"          "sctp"  "[::]"                -
	// "sctp"  "[::]"             "sctp"  "0.0.0.0"             -
	// "sctp"  "[::ffff:0.0.0.0]" "sctp"  "[::]"                -
	// "sctp"  "[::]"             "sctp"  "[::ffff:0.0.0.0]"    -
	// -----------------------------------------------------------
	// "sctp4" ""                 "sctp6" ""                    ok
	// "sctp6" ""                 "sctp4" ""                    ok
	// "sctp4" "0.0.0.0"          "sctp6" "[::]"                ok
	// "sctp6" "[::]"             "sctp4" "0.0.0.0"             ok
	// -----------------------------------------------------------
	// "sctp"  "127.0.0.1"        "sctp"  "[::1]"               ok
	// "sctp"  "[::1]"            "sctp"  "127.0.0.1"           ok
	// "sctp4" "127.0.0.1"        "sctp6" "[::1]"               ok
	// "sctp6" "[::1]"            "sctp4" "127.0.0.1"           ok
	//
	// Platform default configurations:
	// linux, kernel version 3.0.0
	//	net.ipv6.bindv6only=0 (overridable by sysctl or IPV6_V6ONLY option)

	{"sctp", "", "sctp", "", syscall.EADDRINUSE},
	{"sctp", "", "sctp", "0.0.0.0", syscall.EADDRINUSE},
	{"sctp", "0.0.0.0", "sctp", "", syscall.EADDRINUSE},

	{"sctp", "", "sctp", "[::]", syscall.EADDRINUSE},
	{"sctp", "[::]", "sctp", "", syscall.EADDRINUSE},
	{"sctp", "0.0.0.0", "sctp", "[::]", syscall.EADDRINUSE},
	{"sctp", "[::]", "sctp", "0.0.0.0", syscall.EADDRINUSE},
	{"sctp", "[::ffff:0.0.0.0]", "sctp", "[::]", syscall.EADDRINUSE},
	{"sctp", "[::]", "sctp", "[::ffff:0.0.0.0]", syscall.EADDRINUSE},

	{"sctp4", "", "sctp6", "", nil},
	{"sctp6", "", "sctp4", "", nil},
	{"sctp4", "0.0.0.0", "sctp6", "[::]", nil},
	{"sctp6", "[::]", "sctp4", "0.0.0.0", nil},

	{"sctp", "127.0.0.1", "sctp", "[::1]", nil},
	{"sctp", "[::1]", "sctp", "127.0.0.1", nil},
	{"sctp4", "127.0.0.1", "sctp6", "[::1]", nil},
	{"sctp6", "[::1]", "sctp4", "127.0.0.1", nil},
}

// TestDualStackTCPListener tests both single and double listen
// to a test listener with various address families, different
// listening address and same port.
func TestDualStackTCPListener(t *testing.T) {
	if !supportsIPv4() || !supportsIPv6() {
		t.Skip("both IPv4 and IPv6 are required")
	}
	for _, tt := range dualStackSCTPListenerTests {
		if !supportsIPv4map() && differentWildcardAddr(tt.address1, tt.address2) {
			tt.xerr = nil
		}
		var firstErr, secondErr error
		for i := 0; i < 5; i++ {
			lns, err := newDualStackListener()
			if err != nil {
				t.Fatal(err)
			}
			port := lns[0].port()
			for _, ln := range lns {
				_ = ln.Close()
			}
			var ln1 net.Listener
			ln1, firstErr = Listen(tt.network1, tt.address1+":"+port)
			if firstErr != nil {
				continue
			}
			if err := checkFirstListener(tt.network1, ln1); err != nil {
				_ = ln1.Close()
				t.Fatal(err)
			}
			ln2, err := Listen(tt.network2, tt.address2+":"+ln1.(*SCTPListener).port())
			if err == nil {
				_ = ln2.Close()
			}
			if secondErr = checkDualStackSecondListener(tt.network2, tt.address2, err, tt.xerr); secondErr != nil {
				_ = ln1.Close()
				continue
			}
			_ = ln1.Close()
			break
		}
		if firstErr != nil {
			t.Error(firstErr)
		}
		if secondErr != nil {
			t.Error(secondErr)
		}
	}
}

func differentWildcardAddr(i, j string) bool {
	if (i == "" || i == "0.0.0.0" || i == "::ffff:0.0.0.0") && (j == "" || j == "0.0.0.0" || j == "::ffff:0.0.0.0") {
		return false
	}
	if i == "[::]" && j == "[::]" {
		return false
	}
	return true
}

func checkFirstListener(network string, ln any) error {
	c := ln.(*SCTPListener).c
	switch network {
	case "sctp":
		// If a node under test supports both IPv6 capability
		// and IPv6 IPv4-mapping capability, we can assume
		// that the node listens on a wildcard address with an
		// AF_INET6 socket.
		if supportsIPv4map() && c.laddr.Load().isWildcard() {
			if c.family != unix.AF_INET6 {
				return fmt.Errorf("Listen(%s, %v) returns %v; want %v", c.net, c.laddr.Load(), c.family, unix.AF_INET6)
			}
		} else {
			if c.family != c.laddr.Load().family() {
				return fmt.Errorf("Listen(%s, %v) returns %v; want %v", c.net, c.laddr.Load(), c.family, c.laddr.Load().family())
			}
		}

	case "sctp4":
		if c.family != syscall.AF_INET {
			return fmt.Errorf("%v got %v; want %v", c.laddr.Load(), c.family, syscall.AF_INET)
		}
	case "sctp6":
		if c.family != syscall.AF_INET6 {
			return fmt.Errorf("%v got %v; want %v", c.laddr.Load(), c.family, syscall.AF_INET6)
		}
	default:
		return net.UnknownNetworkError(network)
	}
	return nil
}

func checkSecondListener(network, address string, err error) error {
	switch network {
	case "sctp", "sctp4", "sctp6":
		if err == nil {
			return fmt.Errorf("%s should fail", network+" "+address)
		}
	default:
		return net.UnknownNetworkError(network)
	}
	return nil
}

func (ln *SCTPListener) port() string {
	i := strings.LastIndexByte(ln.Addr().String(), ':')
	if i < 0 {
		return ""
	}
	return ln.Addr().String()[i+1:]
}

func checkDualStackSecondListener(network, address string, err, xerr error) error {
	switch network {
	case "sctp", "sctp4", "sctp6":
		if xerr == nil && err != nil || xerr != nil && err == nil {
			return fmt.Errorf("%s got %v; want %v", network+" "+address, err, xerr)
		}
	default:
		return net.UnknownNetworkError(network)
	}
	return nil
}

func newDualStackListener() (lns []*SCTPListener, err error) {
	var args = []struct {
		network string
		SCTPAddr
	}{
		{"sctp4", SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}}},
		{"sctp6", SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv6loopback}}}},
	}
	for i := 0; i < 64; i++ {
		var port int
		var lns []*SCTPListener
		for _, arg := range args {
			arg.SCTPAddr.Port = port
			ln, err := ListenSCTP(arg.network, &arg.SCTPAddr)
			if err != nil {
				continue
			}
			port = ln.Addr().(*SCTPAddr).Port
			lns = append(lns, ln)
		}
		if len(lns) != len(args) {
			for _, ln := range lns {
				_ = ln.Close()
			}
			continue
		}
		return lns, nil
	}
	return nil, errors.New("no dualstack available")
}
