// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the GO_LICENSE file.

// This file contains test code from go's net package, tweaked for SCTP where necessary.

package sctp

import (
	"bufio"
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
}

var prohibitionaryDialArgTests = []struct {
	network string
	address string
}{
	{"sctp6", "127.0.0.1"},
	{"sctp6", "[::ffff:127.0.0.1]"},
}

func TestProhibitionaryDialArgSCTP(t *testing.T) {
	if !supportsIPv4map() {
		t.Skip("mapping ipv4 address inside ipv6 address not supported")
	}

	ln, err := Listen("sctp", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.(*SCTPListener).port()

	for i, tt := range prohibitionaryDialArgTests {
		c, err1 := Dial(tt.network, tt.address+":"+port)
		if err1 == nil {
			c.Close()
			t.Errorf("#%d: %v", i, err1)
		}
	}
}

func TestDialLocalSCTP(t *testing.T) {
	ln := newLocalListenerSCTP(t, "sctp")
	defer ln.Close()
	fmt.Println("Listener: " + ln.Addr().String())

	port := ln.(*SCTPListener).port()
	c, err := Dial("sctp", ":"+port)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(c.LocalAddr().String() + " <----------> " + c.RemoteAddr().String())
	c.Close()
}

func TestDialerDualStackFDLeakSCTP(t *testing.T) {
	t.Skip("Do we need to test for FD leakage? besides package socktest is internal and not accessible")
}

// Define a pair of blackholed (IPv4, IPv6) addresses, for which dialTCP is
// expected to hang until the timeout elapses. These addresses are reserved
// for benchmarking by RFC 6890.
const (
	slowDst6 = "[2001:2::254]"
)

func TestDialParallelSCTP(t *testing.T) {
	t.Skip("we don't do parallel dials")
}

func TestDialerFallbackDelaySCTP(t *testing.T) {
	t.Skip("we don't do parallel dials")
}

func TestDialParallelSpuriousConnection(t *testing.T) {
	t.Skip("we don't do parallel dials")
}

func TestDialerPartialDeadline(t *testing.T) {
	t.Skip("we don't do parallel dials")
}

func TestDialerLocalAddrSCTP(t *testing.T) {
	if !supportsIPv4() || !supportsIPv6() {
		t.Skip("both IPv4 and IPv6 are required")
	}

	type test struct {
		network, raddr string
		laddr          net.Addr
		error
	}
	var tests = []test{
		{"sctp4", "127.0.0.1", nil, nil},
		{"sctp4", "127.0.0.1", &SCTPAddr{}, nil},
		{"sctp4", "127.0.0.1", &SCTPAddr{IPAddrs: []net.IPAddr{}}, nil},
		{"sctp4", "127.0.0.1", &SCTPAddr{IPAddrs: []net.IPAddr{{}}}, nil},
		{"sctp4", "127.0.0.1", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("0.0.0.0")}}}, nil},
		{"sctp4", "127.0.0.1", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("0.0.0.0").To4()}}}, nil},
		{"sctp4", "127.0.0.1", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("::")}}}, &net.AddrError{Err: "some error"}},
		{"sctp4", "127.0.0.1", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("127.0.0.1").To4()}}}, nil},
		{"sctp4", "127.0.0.1", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("0.0.0.0").To16()}}}, nil},
		{"sctp4", "127.0.0.1", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv6loopback}}}, errNoSuitableAddress},
		{"sctp6", "[::1]", nil, nil},
		{"sctp6", "[::1]", &SCTPAddr{}, nil},
		{"sctp6", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{}}, nil},
		{"sctp6", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{{}}}, nil},
		{"sctp6", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("0.0.0.0")}}}, nil},
		{"sctp6", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("0.0.0.0").To4()}}}, nil},
		{"sctp6", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("::")}}}, nil},
		{"sctp6", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("127.0.0.1").To4()}}}, errNoSuitableAddress},
		{"sctp6", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("127.0.0.1").To16()}}}, errNoSuitableAddress},
		{"sctp6", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv6loopback}}}, nil},

		{"sctp", "127.0.0.1", nil, nil},
		{"sctp", "127.0.0.1", &SCTPAddr{}, nil},
		{"sctp", "127.0.0.1", &SCTPAddr{IPAddrs: []net.IPAddr{}}, nil},
		{"sctp", "127.0.0.1", &SCTPAddr{IPAddrs: []net.IPAddr{{}}}, nil},
		{"sctp", "127.0.0.1", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("0.0.0.0")}}}, nil},
		{"sctp", "127.0.0.1", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("0.0.0.0").To4()}}}, nil},
		{"sctp", "127.0.0.1", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("127.0.0.1").To4()}}}, nil},
		{"sctp", "127.0.0.1", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("127.0.0.1").To16()}}}, nil},
		{"sctp", "127.0.0.1", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv6loopback}}}, errNoSuitableAddress},

		{"sctp", "[::1]", nil, nil},
		{"sctp", "[::1]", &SCTPAddr{}, nil},
		{"sctp", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{}}, nil},
		{"sctp", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{{}}}, nil},
		{"sctp", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("0.0.0.0")}}}, nil},
		{"sctp", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("0.0.0.0").To4()}}}, nil},
		{"sctp", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("::")}}}, nil},
		{"sctp", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("127.0.0.1").To4()}}}, errNoSuitableAddress},
		{"sctp", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("127.0.0.1").To16()}}}, errNoSuitableAddress},
		{"sctp", "[::1]", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv6loopback}}}, nil},
	}

	if supportsIPv4map() {
		tests = append(tests, test{
			"sctp", "127.0.0.199", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("::")}}}, nil,
		})
	} else {
		tests = append(tests, test{
			"sctp", "127.0.0.199", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("::")}}}, &net.AddrError{Err: "some error"},
		})
	}
	handler := func(ls *localServerSCTP, ln net.Listener) {
		for {
			c, err := ln.Accept()
			if err != nil {
				log.Printf("gId: %d, Accept error: %v", getGoroutineID(), err)
				return
			}
			log.Printf("gId: %d, Close after accept: %v <----------> %v", getGoroutineID(), c.LocalAddr(), c.RemoteAddr())
			//ls.cl = append(ls.cl, c)
			c.Close()
		}
	}
	var lss [2]*localServerSCTP
	for i, network := range []string{"sctp4", "sctp6"} {
		lss[i] = newLocalServerSCTP(t, network)
		defer lss[i].teardown()
		if err := lss[i].buildup(handler); err != nil {
			t.Fatal(err)
		}
	}

	for _, tt := range tests {
		var d *Dialer
		if tt.laddr == nil {
			d = &Dialer{}
		} else {
			d = &Dialer{LocalAddr: tt.laddr.(*SCTPAddr)}
		}

		var addr string
		ip, err := resolveSCTPAddr("dial", tt.network, tt.raddr+":1", nil)
		if err != nil {
			t.Error(err)
			continue
		}
		if ip.family() == unix.AF_INET {
			addr = lss[0].Listener.Addr().String()
		}
		if ip.family() == unix.AF_INET6 {
			addr = lss[1].Listener.Addr().String()
		}
		log.Printf("gId: %d, About to dial\n", getGoroutineID())
		c, err := d.Dial(context.Background(), tt.network, addr)
		if err == nil && tt.error != nil || err != nil && tt.error == nil {
			t.Errorf("%s %v->%s: got %v; want %v", tt.network, tt.laddr, tt.raddr, err, tt.error)
		}
		if err != nil {
			if perr := parseDialError(err); perr != nil {
				t.Error(perr)
			}
			continue
		}
		log.Printf("gId: %d, Close after dial: %v <----------> %v", getGoroutineID(), c.LocalAddr(), c.RemoteAddr())
		c.Close()
	}
}

func TestDialerDualStackSCTP(t *testing.T) {
	t.Skip("We don't resolve host names to multiple IP addresses, only to one of them")
}

func TestDialerKeepAliveSCTP(t *testing.T) {
	// TO DO: test SCTP hearth beat
}

func TestDialTimeout(t *testing.T) {
	blackholeIPPort := slowDst6 + ":1234"

	d := &Dialer{Timeout: 150 * time.Millisecond}
	errc := make(chan error, 1)
	connc := make(chan net.Conn, 1)
	go func() {
		if c, err := d.Dial(context.Background(), "sctp", blackholeIPPort); err != nil {
			errc <- err
		} else {
			connc <- c
		}
	}()
	for {
		select {
		case c := <-connc:
			c.Close()
			t.Fatal("unexpected successful connection")
		case err := <-errc:
			if oe, ok := err.(*net.OpError); !ok || oe.Err != context.DeadlineExceeded {
				t.Fatalf("dial error = %v (%T); want OpError with Err == context.DeadlineExceeded", err, err)
			}
			return // success.
		case <-time.After(300 * time.Millisecond):
			t.Fatal("waiting too long for the dial to timeout")
		}
	}
}

func TestDialContextTimeout(t *testing.T) {
	blackholeIPPort := slowDst6 + ":1234"

	ctx, cancelFunc := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelFunc()
	d := &Dialer{}
	errc := make(chan error, 1)
	connc := make(chan net.Conn, 1)
	go func() {
		if c, err := d.Dial(ctx, "sctp", blackholeIPPort); err != nil {
			errc <- err
		} else {
			connc <- c
		}
	}()
	for {
		select {
		case c := <-connc:
			c.Close()
			t.Fatal("unexpected successful connection")
		case err := <-errc:
			if oe, ok := err.(*net.OpError); !ok || oe.Err != context.DeadlineExceeded {
				t.Fatalf("dial error = %v (%T); want OpError with Err == context.DeadlineExceeded", err, err)
			}
			return // success.
		case <-time.After(300 * time.Millisecond):
			t.Fatal("waiting too long for the dial to timeout")
		}
	}
}

func TestDialCancel(t *testing.T) {
	blackholeIPPort := slowDst6 + ":1234"
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	const cancelTick = 5 // the timer tick we cancel the dial at
	const timeoutTick = 100

	var d Dialer
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	errc := make(chan error, 1)
	connc := make(chan net.Conn, 1)
	go func() {
		if c, err := d.Dial(ctx, "sctp", blackholeIPPort); err != nil {
			errc <- err
		} else {
			connc <- c
		}
	}()
	ticks := 0
	for {
		select {
		case <-ticker.C:
			ticks++
			if ticks == cancelTick {
				cancelFunc()
			}
			if ticks == timeoutTick {
				t.Fatal("timeout waiting for dial to fail")
			}
		case c := <-connc:
			c.Close()
			t.Fatal("unexpected successful connection")
		case err := <-errc:
			if perr := parseDialError(err); perr != nil {
				t.Error(perr)
			}
			if ticks < cancelTick {
				// Using strings.Contains is ugly but
				// may work on plan9 and windows.
				ignorable := []string{
					"connection refused",
					"unreachable",
					"no route to host",
					"invalid argument",
				}
				e := err.Error()
				for _, ignore := range ignorable {
					if strings.Contains(e, ignore) {
						t.Skipf("connection to %v failed fast with %v", blackholeIPPort, err)
					}
				}

				t.Fatalf("dial error after %d ticks (%d before cancel sent): %v",
					ticks, cancelTick-ticks, err)
			}
			if oe, ok := err.(*net.OpError); !ok || oe.Err != context.Canceled {
				t.Fatalf("dial error = %v (%T); want OpError with Err == context.Canceled", err, err)
			}
			return // success.
		}
	}
}

func TestCancelAfterDialSCTP(t *testing.T) {
	ln := newLocalListenerSCTP(t, "sctp")

	var wg sync.WaitGroup
	wg.Add(1)
	defer func() {
		ln.Close()
		log.Println("in defer func, wait for wg...")
		wg.Wait()
	}()

	// Echo back the first line of each incoming connection.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				break
			}
			log.Printf("connection ACCEPTED: %v <----------> %v", c.LocalAddr(), c.RemoteAddr())
			rb := bufio.NewReader(c)
			log.Printf("reading from accepted connection...")
			line, err := rb.ReadString('\n')
			if err != nil {
				t.Error(err)
				c.Close()
				continue
			}
			log.Printf("reading from accepted connection done, now writing back...")
			if _, err := c.Write([]byte(line)); err != nil {
				t.Error(err)
			}
			log.Printf("gId: %d, CLOSING accepted connection", getGoroutineID())
			c.Close()
		}
		wg.Done()
	}()

	try := func() {
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()
		d := &Dialer{}
		c, err := d.Dial(ctx, "sctp", ln.Addr().String())

		// Immediately after dialing, request cancellation and sleep.
		// Before Issue 15078 was fixed, this would cause subsequent operations
		// to fail with an i/o timeout roughly 50% of the time.
		cancelFunc()
		time.Sleep(10 * time.Millisecond)

		if err != nil {
			t.Fatal(err)
		}
		log.Printf("connection dialed: %v <----------> %v", c.LocalAddr(), c.RemoteAddr())
		defer func(c net.Conn) {
			log.Printf("gId: %d, CLOSING dialed connection in defer", getGoroutineID())
			_ = c.Close()
		}(c)

		// Send some data to confirm that the connection is still alive.
		const message = "echo!\n"
		if _, err := c.Write([]byte(message)); err != nil {
			t.Fatal(err)
		}

		// The server should echo the line, and close the connection.
		rb := bufio.NewReader(c)
		line, err := rb.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line != message {
			t.Errorf("got %q; want %q", line, message)
		}
		if _, err := rb.ReadByte(); err != io.EOF {
			t.Errorf("got %v; want %v", err, io.EOF)
		}

	}

	// This bug manifested about 50% of the time, so try it a few times.
	for i := 0; i < 10; i++ {
		log.Printf("NEXT TRY")
		try()
	}
}

func TestDialClosedPortFailFastSCTP(t *testing.T) {
	for _, network := range []string{"sctp", "sctp4", "sctp6"} {
		t.Run(network, func(t *testing.T) {
			// Reserve a local port till the end of the
			// test by opening a listener and connecting to
			// it using Dial.
			ln := newLocalListenerSCTP(t, network)
			addr := ln.Addr().String()
			conn1, err := Dial(network, addr)
			if err != nil {
				ln.Close()
				t.Fatal(err)
			}
			defer conn1.Close()
			// Now close the listener so the next Dial fails
			// keeping conn1 alive so the port is not made
			// available.
			ln.Close()

			maxElapsed := time.Second
			// The host can be heavy-loaded and take
			// longer than configured. Retry until
			// Dial takes less than maxElapsed or
			// the test times out.
			for {
				startTime := time.Now()
				conn2, err := Dial(network, addr)
				if err == nil {
					conn2.Close()
					t.Fatal("error expected")
				}
				elapsed := time.Since(startTime)
				if elapsed < maxElapsed {
					break
				}
				t.Logf("got %v; want < %v", elapsed, maxElapsed)
			}
		})
	}
}

// Issue 18806: it should always be possible to net.Dial a
// net.Listener().Addr().String when the listen address was ":n", even
// if the machine has halfway configured IPv6 such that it can bind on
// "::" not connect back to that same address.
func TestDialListenerAddrSCTP(t *testing.T) {
	// The original issue report was for listening on just ":0" on a system that
	// supports both tcp4 and tcp6 for external traffic but only tcp4 for loopback
	// traffic. However, the port opened by ":0" is externally-accessible, and may
	// trigger firewall alerts or otherwise be mistaken for malicious activity
	// (see https://go.dev/issue/59497). Moreover, it often does not reproduce
	// the scenario in the issue, in which the port *cannot* be dialed as tcp6.
	//
	// To address both of those problems, we open a tcp4-only localhost port, but
	// then dial the address string that the listener would have reported for a
	// dual-stack port.
	ln, err := Listen("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	t.Logf("listening on %q", ln.Addr())
	port := ln.(*SCTPListener).port()

	// If we had opened a dual-stack port without an explicit "localhost" address,
	// the Listener would arbitrarily report an empty tcp6 address in its Addr
	// string.
	//
	// The documentation for Dial says ‘if the host is empty or a literal
	// unspecified IP address, as in ":80", "0.0.0.0:80" or "[::]:80" for TCP and
	// UDP, "", "0.0.0.0" or "::" for IP, the local system is assumed.’
	// In #18806, it was decided that that should include the local tcp4 host
	// even if the string is in the tcp6 format.
	dialAddr := "[::]:" + port
	c, err := Dial("sctp4", dialAddr)
	if err != nil {
		t.Fatalf(`Dial("tcp4", %q): %v`, dialAddr, err)
	}
	c.Close()
	t.Logf(`Dial("tcp4", %q) succeeded`, dialAddr)
}

func TestDialerControlSCTP(t *testing.T) {
	t.Run("StreamDial", func(t *testing.T) {
		for _, network := range []string{"sctp", "sctp4", "sctp6"} {
			ln := newLocalListenerSCTP(t, network)
			defer ln.Close()
			d := Dialer{Control: controlOnConnSetup}
			c, err := d.Dial(context.Background(), network, ln.Addr().String())
			if err != nil {
				t.Error(err)
				continue
			}
			c.Close()
		}
	})
}

func TestDialerControlContext(t *testing.T) {
	t.Run("StreamDial", func(t *testing.T) {
		for i, network := range []string{"sctp", "sctp4", "sctp6"} {
			t.Run(network, func(t *testing.T) {
				ln := newLocalListenerSCTP(t, network)
				defer ln.Close()
				var id int
				d := Dialer{ControlContext: func(ctx context.Context, network string, address string, c syscall.RawConn) error {
					id = ctx.Value("id").(int)
					return controlOnConnSetup(network, address, c)
				}}
				c, err := d.Dial(context.WithValue(context.Background(), "id", i+1), network, ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				if id != i+1 {
					t.Errorf("got id %d, want %d", id, i+1)
				}
				c.Close()
			})
		}
	})
}

type contextWithNonZeroDeadline struct {
	context.Context
}

func (contextWithNonZeroDeadline) Deadline() (time.Time, bool) {
	// Return non-zero time.Time value with false indicating that no deadline is set.
	return time.Unix(0, 0), false
}

func TestDialWithNonZeroDeadline(t *testing.T) {
	ln := newLocalListenerSCTP(t, "sctp")
	defer ln.Close()
	port := ln.(*SCTPListener).port()

	ctx := contextWithNonZeroDeadline{Context: context.Background()}
	var dialer Dialer
	c, err := dialer.Dial(ctx, "sctp", ":"+port)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
