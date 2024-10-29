package sctp

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"strings"
	"syscall"
	"testing"
)

var tcpListenerTests = []struct {
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

var tcpListenerNilAddressTests = []struct {
	network string
	address string
}{
	{"sctp4", ""},
	{"sctp6", ""},
	{"sctp", ""},
}

// TestTCPListener tests both single and double listen to a test
// listener with same address family, same listening address and
// same port.
func TestTCPListener(t *testing.T) {
	for _, tt := range tcpListenerTests {
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

	// test empty addresses without adding port number
	for _, tt := range tcpListenerNilAddressTests {
		ln1, err := Listen(tt.network, tt.address)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkFirstListener(tt.network, ln1); err != nil {
			_ = ln1.Close()
			t.Fatal(err)
		}
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
