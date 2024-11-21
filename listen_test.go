// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the GO_LICENSE file.

// This file contains test code from go's net package, tweaked for SCTP where necessary.

package sctp

import (
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
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
	//{"sctp6", "[::1]/[fe80::1%lo]/[fe80::2%lo]"}, // additional local ipv6 addresses needed
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
func TestDualStackSCTPListener(t *testing.T) {
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
	fd := ln.(*SCTPListener).fd
	switch network {
	case "sctp":
		// If a node under test supports both IPv6 capability
		// and IPv6 IPv4-mapping capability, we can assume
		// that the node listens on a wildcard address with an
		// AF_INET6 socket.
		if supportsIPv4map() && fd.laddr.Load().isWildcard() {
			if fd.family != unix.AF_INET6 {
				return fmt.Errorf("Listen(%s, %v) returns %v; want %v", fd.net, fd.laddr.Load(), fd.family, unix.AF_INET6)
			}
		} else {
			if fd.family != fd.laddr.Load().family() {
				return fmt.Errorf("Listen(%s, %v) returns %v; want %v", fd.net, fd.laddr.Load(), fd.family, fd.laddr.Load().family())
			}
		}

	case "sctp4":
		if fd.family != syscall.AF_INET {
			return fmt.Errorf("%v got %v; want %v", fd.laddr.Load(), fd.family, syscall.AF_INET)
		}
	case "sctp6":
		if fd.family != syscall.AF_INET6 {
			return fmt.Errorf("%v got %v; want %v", fd.laddr.Load(), fd.family, syscall.AF_INET6)
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

func TestWildWildcardSCTPListener(t *testing.T) {
	if ln, err := Listen("sctp", ""); err == nil {
		ln.Close()
	} else {
		log.Fatal(err)
	}
	if ln, err := ListenSCTP("sctp", nil); err == nil {
		ln.Close()
	} else {
		log.Fatal(err)
	}
}

func TestClosingSCTPListener(t *testing.T) {
	ln := newLocalListenerSCTP(t, "sctp")
	addr := ln.Addr()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	// Let the goroutine start. We don't sleep long: if the
	// goroutine doesn't start, the test will pass without really
	// testing anything, which is OK.
	time.Sleep(time.Millisecond)

	ln.Close()

	ln2, err := Listen("sctp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	ln2.Close()
}

func TestListenConfigControlSCTP(t *testing.T) {
	t.Run("StreamListen", func(t *testing.T) {
		for _, network := range []string{"sctp", "sctp4", "sctp6"} {
			ln := newLocalListenerSCTP(t, network, &ListenConfig{Control: controlOnConnSetup})
			ln.Close()
		}
	})
}

func TestListenerBindAddRemove(t *testing.T) {
	ln1, err := Listen("sctp4", "127.0.0.1/127.0.0.2/127.0.0.3/127.0.0.4:0")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("ln1 address before: ", ln1.Addr())
	ln1SCTP := ln1.(*SCTPListener)
	err = ln1SCTP.BindRemove("127.0.0.2/127.0.0.1:" + ln1SCTP.port())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ln1.Addr().String(), "127.0.0.1") ||
		strings.Contains(ln1.Addr().String(), "127.0.0.2") {
		t.Fatal(err)
	}
	fmt.Println("ln1 address after: ", ln1.Addr())
	err = ln1SCTP.BindAdd("127.0.0.2/127.0.0.1:" + ln1SCTP.port())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ln1.Addr().String(), "127.0.0.1") ||
		!strings.Contains(ln1.Addr().String(), "127.0.0.2") {
		t.Fatal(err)
	}
	fmt.Println("ln1 address after: ", ln1.Addr())
	_ = ln1.Close()

	//
	ln1, err = Listen("sctp", "[::1]/127.0.0.1/127.0.0.2/127.0.0.3/127.0.0.4:0")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("ln1 address before: ", ln1.Addr())
	ln1SCTP = ln1.(*SCTPListener)
	err = ln1SCTP.BindRemove("[::1]/127.0.0.2/127.0.0.1:" + ln1SCTP.port())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ln1.Addr().String(), "127.0.0.1") ||
		strings.Contains(ln1.Addr().String(), "127.0.0.2") ||
		strings.Contains(ln1.Addr().String(), "::1") {
		t.Fatal(err)
	}
	fmt.Println("ln1 address after: ", ln1.Addr())

	err = ln1SCTP.BindAdd("[::1]/127.0.0.2/127.0.0.1:" + ln1SCTP.port())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ln1.Addr().String(), "127.0.0.1") ||
		!strings.Contains(ln1.Addr().String(), "127.0.0.2") ||
		!strings.Contains(ln1.Addr().String(), "::1") {
		t.Fatal(err)
	}
	fmt.Println("ln1 address after: ", ln1.Addr())
	_ = ln1.Close()
}
