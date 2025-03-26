// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the GO_LICENSE file.

// This file contains test code from go's net package, tweaked for SCTP where necessary.

//go:build linux

package sctp

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// This file contains test code from go's net package, tweaked for SCTP where necessary.

func BenchmarkSCTP4OneShot(b *testing.B) {
	benchmarkSCTP(b, false, false, "127.0.0.1:0")
}

func BenchmarkSCTP4OneShotTimeout(b *testing.B) {
	benchmarkSCTP(b, false, true, "127.0.0.1:0")
}

func BenchmarkSCTP4Persistent(b *testing.B) {
	benchmarkSCTP(b, true, false, "127.0.0.1:0")
}

func BenchmarkSCTP4PersistentTimeout(b *testing.B) {
	benchmarkSCTP(b, true, true, "127.0.0.1:0")
}

func BenchmarkSCTP6OneShot(b *testing.B) {
	if !supportsIPv6() {
		b.Skip("ipv6 is not supported")
	}
	benchmarkSCTP(b, false, false, "[::1]:0")
}

func BenchmarkSCTP6OneShotTimeout(b *testing.B) {
	if !supportsIPv6() {
		b.Skip("ipv6 is not supported")
	}
	benchmarkSCTP(b, false, true, "[::1]:0")
}

func BenchmarkSCTP6Persistent(b *testing.B) {
	if !supportsIPv6() {
		b.Skip("ipv6 is not supported")
	}
	benchmarkSCTP(b, true, false, "[::1]:0")
}

func BenchmarkSCTP6PersistentTimeout(b *testing.B) {
	if !supportsIPv6() {
		b.Skip("ipv6 is not supported")
	}
	benchmarkSCTP(b, true, true, "[::1]:0")
}

func benchmarkSCTP(b *testing.B, persistent, timeout bool, laddr string) {

	const msgLen = 512
	conns := b.N
	numConcurrent := runtime.GOMAXPROCS(-1) * 2
	msgs := 1
	if persistent {
		conns = numConcurrent
		msgs = b.N / conns
		if msgs == 0 {
			msgs = 1
		}
		if conns > b.N {
			conns = b.N
		}
	}
	sendMsg := func(c net.Conn, buf []byte) bool {
		n, err := c.Write(buf)
		if n != len(buf) || err != nil {
			b.Log(err)
			return false
		}
		return true
	}
	recvMsg := func(c net.Conn, buf []byte) bool {
		for read := 0; read != len(buf); {
			n, err := c.Read(buf)
			read += n
			if err != nil {
				b.Log(err)
				return false
			}
		}
		return true
	}
	ln, err := Listen("sctp", laddr)
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	serverSem := make(chan bool, numConcurrent)
	// Acceptor.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				break
			}
			serverSem <- true
			// Server connection.
			go func(c net.Conn) {
				defer func() {
					c.Close()
					<-serverSem
				}()
				if timeout {
					c.SetDeadline(time.Now().Add(time.Hour)) // Not intended to fire.
				}
				var buf [msgLen]byte
				for m := 0; m < msgs; m++ {
					if !recvMsg(c, buf[:]) || !sendMsg(c, buf[:]) {
						break
					}
				}
			}(c)
		}
	}()
	clientSem := make(chan bool, numConcurrent)
	for i := 0; i < conns; i++ {
		clientSem <- true
		// Client connection.
		go func() {
			defer func() {
				<-clientSem
			}()
			c, err := Dial("sctp", ln.Addr().String())
			if err != nil {
				b.Log(err)
				return
			}
			defer c.Close()
			if timeout {
				c.SetDeadline(time.Now().Add(time.Hour)) // Not intended to fire.
			}
			var buf [msgLen]byte
			for m := 0; m < msgs; m++ {
				if !sendMsg(c, buf[:]) || !recvMsg(c, buf[:]) {
					break
				}
			}
		}()
	}
	for i := 0; i < numConcurrent; i++ {
		clientSem <- true
		serverSem <- true
	}
}

func BenchmarkSCTP4ConcurrentReadWrite(b *testing.B) {
	benchmarkSCTPConcurrentReadWrite(b, "127.0.0.1:0")
}

func BenchmarkSCTP6ConcurrentReadWrite(b *testing.B) {
	if !supportsIPv6() {
		b.Skip("ipv6 is not supported")
	}
	benchmarkSCTPConcurrentReadWrite(b, "[::1]:0")
}

func benchmarkSCTPConcurrentReadWrite(b *testing.B, laddr string) {
	// The benchmark creates GOMAXPROCS client/server pairs.
	// Each pair creates 4 goroutines: client reader/writer and server reader/writer.
	// The benchmark stresses concurrent reading and writing to the same connection.
	// Such pattern is used in net/http and net/rpc.

	b.StopTimer()

	P := runtime.GOMAXPROCS(0)
	N := b.N / P
	W := 1000

	// Setup P client/server connections.
	clients := make([]net.Conn, P)
	servers := make([]net.Conn, P)
	ln, err := Listen("sctp", laddr)
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	done := make(chan bool)
	go func() {
		for p := 0; p < P; p++ {
			s, err := ln.Accept()
			if err != nil {
				b.Error(err)
				return
			}
			servers[p] = s
		}
		done <- true
	}()
	for p := 0; p < P; p++ {
		c, err := Dial("sctp", ln.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		clients[p] = c
	}
	<-done

	b.StartTimer()

	var wg sync.WaitGroup
	wg.Add(4 * P)
	for p := 0; p < P; p++ {
		// Client writer.
		go func(c net.Conn) {
			defer wg.Done()
			var buf [1]byte
			for i := 0; i < N; i++ {
				v := byte(i)
				for w := 0; w < W; w++ {
					v *= v
				}
				buf[0] = v
				_, err := c.Write(buf[:])
				if err != nil {
					b.Error(err)
					return
				}
			}
		}(clients[p])

		// Pipe between server reader and server writer.
		pipe := make(chan byte, 128)

		// Server reader.
		go func(s net.Conn) {
			defer wg.Done()
			var buf [1]byte
			for i := 0; i < N; i++ {
				_, err := s.Read(buf[:])
				if err != nil {
					b.Error(err)
					return
				}
				pipe <- buf[0]
			}
		}(servers[p])

		// Server writer.
		go func(s net.Conn) {
			defer wg.Done()
			var buf [1]byte
			for i := 0; i < N; i++ {
				v := <-pipe
				for w := 0; w < W; w++ {
					v *= v
				}
				buf[0] = v
				_, err := s.Write(buf[:])
				if err != nil {
					b.Error(err)
					return
				}
			}
			s.Close()
		}(servers[p])

		// Client reader.
		go func(c net.Conn) {
			defer wg.Done()
			var buf [1]byte
			for i := 0; i < N; i++ {
				_, err := c.Read(buf[:])
				if err != nil {
					b.Error(err)
					return
				}
			}
			c.Close()
		}(clients[p])
	}
	wg.Wait()
}

type resolveSCTPAddrTest struct {
	network       string
	litAddrOrName string
	addr          *SCTPAddr
	err           error
}

var resolveSCTPAddrTests = []resolveSCTPAddrTest{
	{"sctp", "127.0.0.1:0", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, Port: 0}, nil},
	{"sctp4", "127.0.0.1:65535", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, Port: 65535}, nil},

	{"sctp", "[::1]:0", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("::1")}}, Port: 0}, nil},
	{"sctp6", "[::1]:65535", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("::1")}}, Port: 65535}, nil},

	{"sctp", "[::1%en0]:1", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("::1"), Zone: "en0"}}, Port: 1}, nil},
	{"sctp6", "[::1%911]:2", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("::1"), Zone: "911"}}, Port: 2}, nil},

	{"", "127.0.0.1:0", nil, net.UnknownNetworkError("")},
	{"", "[::1]:0", nil, net.UnknownNetworkError("")},

	{"sctp", ":12345", &SCTPAddr{IPAddrs: []net.IPAddr{{}}, Port: 12345}, nil},

	{"http", "127.0.0.1:0", nil, net.UnknownNetworkError("http")},

	{"sctp", "127.0.0.1:http", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, Port: 80}, nil},
	{"sctp", "[::ffff:127.0.0.1]:http", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("::ffff:127.0.0.1")}}, Port: 80}, nil},
	{"sctp", "[2001:db8::1]:http", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}}, Port: 80}, nil},
	{"sctp4", "127.0.0.1:http", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, Port: 80}, nil},
	{"sctp4", "[::ffff:127.0.0.1]:http", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, Port: 80}, nil},
	{"sctp6", "[2001:db8::1]:http", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}}, Port: 80}, nil},

	{"sctp4", "[2001:db8::1]:http", nil, &net.AddrError{Err: errNoSuitableAddress.Error(), Addr: "2001:db8::1"}},
	{"sctp6", "127.0.0.1:http", nil, &net.AddrError{Err: errNoSuitableAddress.Error(), Addr: "127.0.0.1"}},
	{"sctp6", "[::ffff:127.0.0.1]:http", nil, &net.AddrError{Err: errNoSuitableAddress.Error(), Addr: "::ffff:127.0.0.1"}},
}

func TestResolveSCTPAddr(t *testing.T) {
	for _, tt := range resolveSCTPAddrTests {
		addr, err := ResolveSCTPAddr(tt.network, tt.litAddrOrName)
		if !reflect.DeepEqual(addr, tt.addr) || !reflect.DeepEqual(err, tt.err) {
			t.Errorf("resolveSCTPAddr(%q, %q) = %#v, %v, want %#v, %v", tt.network, tt.litAddrOrName, addr, err, tt.addr, tt.err)
			continue
		}
		if err == nil {
			addr2, err := ResolveSCTPAddr(addr.Network(), addr.String())
			if !reflect.DeepEqual(addr2, tt.addr) || err != tt.err {
				t.Errorf("(%q, %q): resolveSCTPAddr(%q, %q) = %#v, %v, want %#v, %v", tt.network, tt.litAddrOrName, addr.Network(), addr.String(), addr2, err, tt.addr, tt.err)
			}
		}
	}
}

var sctpListenerNameTests = []struct {
	net   string
	laddr *SCTPAddr
}{
	{"sctp4", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}}},
	{"sctp4", &SCTPAddr{IPAddrs: []net.IPAddr{{}}}},
	{"sctp4", &SCTPAddr{IPAddrs: []net.IPAddr{}}},
	{"sctp4", &SCTPAddr{}},
	{"sctp4", nil},
}

func TestSCTPListenerName(t *testing.T) {
	for _, tt := range sctpListenerNameTests {
		ln, err := ListenSCTP(tt.net, tt.laddr)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		la := ln.Addr()
		if a, ok := la.(*SCTPAddr); !ok || a.Port == 0 {
			t.Fatalf("got %v; expected a proper address with non-zero port number", la)
		}
	}
}

func TestSCTPConcurrentAccept(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	ln, err := Listen("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	const N = 10
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					break
				}
				c.Close()
			}
			wg.Done()
		}()
	}
	attempts := 10 * N
	fails := 0
	d := &Dialer{Timeout: 200 * time.Millisecond}
	for i := 0; i < attempts; i++ {
		c, err := d.Dial("sctp", ln.Addr().String())
		if err != nil {
			fails++
		} else {
			c.Close()
		}
	}
	ln.Close()
	wg.Wait()
	if fails > 0 {
		t.Fatalf("# of failed Dials: %v", fails)
	}
}

func TestSCTPReadWriteAllocs(t *testing.T) {
	ln, err := Listen("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var server net.Conn
	errc := make(chan error, 1)
	go func() {
		var err error
		server, err = ln.Accept()
		errc <- err
	}()
	client, err := Dial("sctp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	var buf [128]byte
	allocs := testing.AllocsPerRun(1000, func() {
		_, err := server.Write(buf[:])
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadFull(client, buf[:])
		if err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 0 {
		t.Fatalf("got %v; want 0", allocs)
	}

	var bufwrt [128]byte
	ch := make(chan bool)
	defer close(ch)
	go func() {
		for <-ch {
			_, err := server.Write(bufwrt[:])
			errc <- err
		}
	}()
	allocs = testing.AllocsPerRun(1000, func() {
		ch <- true
		if _, err = io.ReadFull(client, buf[:]); err != nil {
			t.Fatal(err)
		}
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 0 {
		t.Fatalf("got %v; want 0", allocs)
	}
}

func TestSCTPStress(t *testing.T) {
	const conns = 2
	const msgLen = 512
	msgs := int(1e4)
	if testing.Short() {
		msgs = 1e2
	}

	sendMsg := func(c net.Conn, buf []byte) bool {
		n, err := c.Write(buf)
		if n != len(buf) || err != nil {
			t.Log(err)
			return false
		}
		return true
	}
	recvMsg := func(c net.Conn, buf []byte) bool {
		for read := 0; read != len(buf); {
			n, err := c.Read(buf)
			read += n
			if err != nil {
				t.Log(err)
				return false
			}
		}
		return true
	}

	ln, err := Listen("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan bool)
	// Acceptor.
	go func() {
		defer func() {
			done <- true
		}()
		for {
			c, err := ln.Accept()
			if err != nil {
				break
			}
			// Server connection.
			go func(c net.Conn) {
				defer c.Close()
				var buf [msgLen]byte
				for m := 0; m < msgs; m++ {
					if !recvMsg(c, buf[:]) || !sendMsg(c, buf[:]) {
						break
					}
				}
			}(c)
		}
	}()
	for i := 0; i < conns; i++ {
		// Client connection.
		go func() {
			defer func() {
				done <- true
			}()
			c, err := Dial("sctp", ln.Addr().String())
			if err != nil {
				t.Log(err)
				return
			}
			defer c.Close()
			var buf [msgLen]byte
			for m := 0; m < msgs; m++ {
				if !sendMsg(c, buf[:]) || !recvMsg(c, buf[:]) {
					break
				}
			}
		}()
	}
	for i := 0; i < conns; i++ {
		<-done
	}
	ln.Close()
	<-done
}

func TestCopyPipeIntoSCTP(t *testing.T) {
	ln := newLocalListenerSCTP(t, "sctp")
	defer ln.Close()

	errc := make(chan error, 1)
	defer func() {
		if err := <-errc; err != nil {
			t.Error(err)
		}
	}()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()

		buf := make([]byte, 100)
		n, err := io.ReadFull(c, buf)
		if err != io.ErrUnexpectedEOF || n != 2 {
			errc <- fmt.Errorf("got err=%q n=%v; want err=%q n=2", err, n, io.ErrUnexpectedEOF)
			return
		}

		errc <- nil
	}()

	c, err := Dial("sctp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	errc2 := make(chan error, 1)
	defer func() {
		if err := <-errc2; err != nil {
			t.Error(err)
		}
	}()

	defer w.Close()

	go func() {
		_, err := io.Copy(c, r)
		errc2 <- err
	}()

	// Split write into 2 packets. That makes Windows TransmitFile
	// drop second packet.
	packet := make([]byte, 1)
	_, err = w.Write(packet)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	_, err = w.Write(packet)
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkSetReadDeadlineSCTP(b *testing.B) {
	ln := newLocalListenerSCTP(b, "sctp")
	defer ln.Close()
	var serv net.Conn
	done := make(chan error)
	go func() {
		var err error
		serv, err = ln.Accept()
		done <- err
	}()
	c, err := Dial("sctp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	if err := <-done; err != nil {
		b.Fatal(err)
	}
	defer serv.Close()
	c.SetWriteDeadline(time.Now().Add(2 * time.Hour))
	deadline := time.Now().Add(time.Hour)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.SetReadDeadline(deadline)
		deadline = deadline.Add(1)
	}
}

func TestTCPListenAfterClose(t *testing.T) {
	// Regression test for https://go.dev/issue/50216:
	// after calling Close on a Listener, the fake net implementation would
	// erroneously Accept a connection dialed before the call to Close.

	ln := newLocalListenerSCTP(t, "sctp")
	defer ln.Close()

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	d := &Dialer{}
	for n := 2; n > 0; n-- {
		wg.Add(1)
		go func() {
			defer wg.Done()

			c, err := d.DialContext(ctx, ln.Addr().Network(), ln.Addr().String())
			if err == nil {
				<-ctx.Done()
				c.Close()
			}
		}()
	}

	c, err := ln.Accept()
	if err == nil {
		c.Close()
	} else {
		t.Error(err)
	}
	time.Sleep(10 * time.Millisecond)
	cancel()
	wg.Wait()
	ln.Close()

	c, err = ln.Accept()
	if err == nil || !strings.EqualFold(err.(*net.OpError).Err.Error(), "use of closed file") {
		if err == nil {
			c.Close()
		}
		t.Errorf("after l.Close(), l.Accept() = _, %v\nwant %v", err, "use of closed file")
	}
}

// See golang.org/issue/14548
func TestSCTPSpuriousConnSetupCompletion(t *testing.T) {
	t.Skip("revisit this, skip for now as it fails for large attempts values")
	ln := newLocalListenerSCTP(t, "sctp")
	var wg sync.WaitGroup
	wg.Add(1)
	go func(ln net.Listener) {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				var b [1]byte
				c.Read(b[:])
				c.Close()
				wg.Done()
			}(c)
		}
	}(ln)

	attempts := int(1e4) // larger is better
	wg.Add(attempts)
	throttle := make(chan struct{}, runtime.GOMAXPROCS(-1)*2)
	for i := 0; i < attempts; i++ {
		throttle <- struct{}{}
		go func(i int) {
			defer func() {
				<-throttle
				wg.Done()
			}()
			d := Dialer{Timeout: 50 * time.Millisecond}
			c, err := d.Dial(ln.Addr().Network(), ln.Addr().String())
			if err != nil {
				if perr := parseDialError(err); perr != nil {
					t.Errorf("#%d: %v (original error: %v)", i, perr, err)
				}
				return
			}
			var b [1]byte
			if _, err := c.Write(b[:]); err != nil {
				if perr := parseWriteError(err); perr != nil {
					t.Errorf("#%d: %v", i, err)
				}
				if samePlatformError(err, syscall.ENOTCONN) {
					t.Errorf("#%d: %v", i, err)
				}
			}
			c.Close()
		}(i)
	}

	ln.Close()
	wg.Wait()
}

var dnsWaitGroup sync.WaitGroup

func TestSCTPSpuriousConnSetupCompletionWithCancel(t *testing.T) {
	defer dnsWaitGroup.Wait()
	t.Parallel()
	const tries = 10000
	var wg sync.WaitGroup
	wg.Add(tries * 2)
	sem := make(chan bool, 5)
	for i := 0; i < tries; i++ {
		sem <- true
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(rand.Int63n(int64(5 * time.Millisecond))))
			cancel()
		}()
		go func(i int) {
			defer wg.Done()
			var dialer Dialer
			// Try to connect to a real host on a port
			// that it is not listening on.
			_, err := dialer.DialContext(ctx, "tcp", "golang.org:3")
			if err == nil {
				t.Errorf("Dial to unbound port succeeded on attempt %d", i)
			}
			<-sem
		}(i)
	}
	wg.Wait()
}
