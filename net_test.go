// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the GO_LICENSE file.

// This file contains test code from go's net package, tweaked for SCTP where necessary.

//go:build linux

package sctp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestCloseReadSCTP(t *testing.T) {
	network := "sctp"
	if !testableNetwork(network) {
		t.Skipf("network %s is not testable on the current platform", network)
	}

	ln := newLocalListenerSCTP(t, network)
	defer ln.Close()

	c, err := Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	err = c.(*SCTPConn).CloseRead()
	if err != nil {
		if perr := parseCloseError(err, true); perr != nil {
			t.Error(perr)
		}
		t.Fatal(err)
	}
	var b [1]byte
	n, err := c.Read(b[:])
	if n != 0 || err == nil {
		t.Fatalf("got (%d, %v); want (0, error)", n, err)
	}
}

func TestCloseWriteSCTP(t *testing.T) {
	deadline, _ := t.Deadline()
	if !deadline.IsZero() {
		// Leave 10% headroom on the deadline to report errors and clean up.
		deadline = deadline.Add(-time.Until(deadline) / 10)
	}

	network := "sctp"
	if !testableNetwork(network) {
		t.Skipf("network %s is not testable on the current platform", network)
	}

	handler := func(ls *localServerSCTP, ln net.Listener) {
		c, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}

		if !deadline.IsZero() {
			c.SetDeadline(deadline)
		}
		defer c.Close()

		var b [1]byte
		n, err := c.Read(b[:])
		if n != 0 || err != io.EOF {
			t.Errorf("got (%d, %v); want (0, io.EOF)", n, err)
			return
		}
		if err == nil {
			t.Errorf("got (%d, %v); want (any, error)", n, err)
			return
		}
	}

	ls := newLocalServerSCTP(t, network)
	defer ls.teardown()
	if err := ls.buildup(handler); err != nil {
		t.Fatal(err)
	}

	c, err := Dial(ls.Listener.Addr().Network(), ls.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	if !deadline.IsZero() {
		c.SetDeadline(deadline)
	}
	defer c.Close()

	err = c.(*SCTPConn).CloseWrite()
	if err != nil {
		if perr := parseCloseError(err, true); perr != nil {
			t.Error(perr)
		}
		t.Fatal(err)
	}
	var b [1]byte

	n, err := c.Write(b[:])
	if err == nil {
		t.Fatalf("got (%d, %v); want (any, error)", n, err)
	}
}

func TestConnCloseSCTP(t *testing.T) {
	network := "sctp"
	if !testableNetwork(network) {
		t.Skipf("network %s is not testable on the current platform", network)
	}

	ln := newLocalListenerSCTP(t, network)
	defer ln.Close()

	c, err := Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := c.Close(); err != nil {
		if perr := parseCloseError(err, false); perr != nil {
			t.Error(perr)
		}
		t.Fatal(err)
	}
	var b [1]byte
	n, err := c.Read(b[:])
	if n != 0 || err == nil {
		t.Fatalf("got (%d, %v); want (0, error)", n, err)
	}
}

func TestListenerCloseSCTP(t *testing.T) {
	network := "sctp"
	if !testableNetwork(network) {
		t.Skipf("network %s is not testable on the current platform", network)
	}

	ln := newLocalListenerSCTP(t, network)
	if err := ln.Close(); err != nil {
		if perr := parseCloseError(err, false); perr != nil {
			t.Error(perr)
		}
		t.Fatal(err)
	}
	c, err := ln.Accept()
	if err == nil {
		c.Close()
		t.Fatal("should fail")
	}

	// Note: we cannot ensure that a subsequent Dial does not succeed, because
	// we do not in general have any guarantee that ln.Addr is not immediately
	// reused.
}

func TestListenCloseListenSCTP(t *testing.T) {
	const maxTries = 10
	for tries := 0; tries < maxTries; tries++ {
		ln := newLocalListenerSCTP(t, "sctp")
		addr := ln.Addr().String()
		// TODO: This is racy. The selected address could be reused in between this
		// Close and the subsequent Listen.
		if err := ln.Close(); err != nil {
			if perr := parseCloseError(err, false); perr != nil {
				t.Error(perr)
			}
			t.Fatal(err)
		}
		ln, err := Listen("sctp", addr)
		if err == nil {
			// Success
			ln.Close()
			return
		}
		t.Errorf("failed on try %d/%d: %v", tries+1, maxTries, err)
	}
	t.Fatalf("failed to listen/close/listen on same address after %d tries", maxTries)
}

func TestZeroByteRead(t *testing.T) {
	network := "sctp"
	if !testableNetwork(network) {
		t.Skipf("network %s is not testable on the current platform", network)
	}

	ln := newLocalListenerSCTP(t, network)
	connc := make(chan net.Conn, 1)
	defer func() {
		ln.Close()
		for c := range connc {
			if c != nil {
				c.Close()
			}
		}
	}()
	go func() {
		defer close(connc)
		c, err := ln.Accept()
		if err != nil {
			t.Error(err)
		}
		connc <- c // might be nil
	}()
	c, err := Dial(network, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sc := <-connc
	if sc == nil {
		return
	}
	defer sc.Close()

	n, err := c.Read(nil)
	if n != 0 || err != nil {
		t.Errorf("%s: zero byte client read = %v, %v; want 0, nil", network, n, err)
	}

	n, err = sc.Read(nil)
	if n != 0 || err != nil {
		t.Errorf("%s: zero byte server read = %v, %v; want 0, nil", network, n, err)
	}
}

// Tests that a blocked Read is interrupted by a concurrent SetReadDeadline
// modifying that Conn's read deadline to the past.
// See golang.org/cl/30164 which documented this. The net/http package
// depends on this.
func TestReadTimeoutUnblocksReadSCTP(t *testing.T) {
	serverDone := make(chan struct{})
	server := func(cs *SCTPConn) error {
		defer close(serverDone)
		errc := make(chan error, 1)
		go func() {
			defer close(errc)
			go func() {
				// TODO: find a better way to wait
				// until we're blocked in the cs.Read
				// call below. Sleep is lame.
				time.Sleep(50 * time.Millisecond)

				// Interrupt the upcoming Read, unblocking it:
				cs.SetReadDeadline(time.Unix(123, 0)) // time in the past
			}()
			var buf [1]byte
			n, err := cs.Read(buf[:1])
			if n != 0 || err == nil {
				errc <- fmt.Errorf("Read = %v, %v; want 0, non-nil", n, err)
			}
		}()
		select {
		case err := <-errc:
			return err
		case <-time.After(5 * time.Second):
			buf := make([]byte, 2<<20)
			buf = buf[:runtime.Stack(buf, true)]
			println("Stacks at timeout:\n", string(buf))
			return errors.New("timeout waiting for Read to finish")
		}

	}
	// Do nothing in the client. Never write. Just wait for the
	// server's half to be done.
	client := func(*SCTPConn) error {
		<-serverDone
		return nil
	}
	withSCTPConnPair(t, client, server)
}

// withSCTPConnPair sets up a TCP connection between two peers, then
// runs peer1 and peer2 concurrently. withSCTPConnPair returns when
// both have completed.
func withSCTPConnPair(t *testing.T, peer1, peer2 func(c *SCTPConn) error) {
	t.Helper()
	ln := newLocalListenerSCTP(t, "sctp")
	defer ln.Close()
	errc := make(chan error, 2)
	go func() {
		c1, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		err = peer1(c1.(*SCTPConn))
		c1.Close()
		errc <- err
	}()
	go func() {
		c2, err := Dial("sctp", ln.Addr().String())
		if err != nil {
			errc <- err
			return
		}
		err = peer2(c2.(*SCTPConn))
		c2.Close()
		errc <- err
	}()
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil {
			t.Error(err)
		}
	}
}

// verify that a blocked Read is woken up by a Close.
func TestCloseUnblocksReadSCTP(t *testing.T) {
	server := func(cs *SCTPConn) error {
		// Give the client time to get stuck in a Read:
		time.Sleep(20 * time.Millisecond)
		cs.Close()
		return nil
	}
	client := func(ss *SCTPConn) error {
		n, err := ss.Read([]byte{0})
		if n != 0 || err != io.EOF {
			return fmt.Errorf("Read = %v, %v; want 0, EOF", n, err)
		}
		return nil
	}
	withSCTPConnPair(t, client, server)
}

// Go Issue 24808: verify that ECONNRESET is not temporary for read.
func TestNotTemporaryReadSCTP(t *testing.T) {
	ln := newLocalListenerSCTP(t, "sctp")
	serverDone := make(chan struct{})
	dialed := make(chan struct{})
	go func() {
		defer close(serverDone)

		cs, err := ln.Accept()
		if err != nil {
			return
		}
		<-dialed
		cs.(*SCTPConn).SetLinger(0)
		cs.Close()
	}()
	defer func() {
		ln.Close()
		<-serverDone
	}()

	ss, err := Dial("sctp", ln.Addr().String())
	close(dialed)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()

	_, err = ss.Read([]byte{0})
	if err == nil {
		t.Fatal("Read succeeded unexpectedly")
	} else if err == io.EOF {
		t.Fatal("Read unexpectedly returned io.EOF after socket was abruptly closed")
	}
	if ne, ok := err.(net.Error); !ok {
		t.Errorf("Read error does not implement net.Error: %v", err)
	} else if ne.Temporary() {
		t.Errorf("Read error is unexpectedly temporary: %v", err)
	}
}
