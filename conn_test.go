// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the GO_LICENSE file.

// This file contains test code from go's net package, tweaked for SCTP where necessary.

//go:build linux

package sctp

import (
	"net"
	"testing"
	"time"
)

func TestConnAndListenerSCTP(t *testing.T) {
	network := "sctp"
	if !testableNetwork(network) {
		t.Skipf("skipping %s test", network)
	}

	ls := newLocalServerSCTP(t, network)
	defer ls.teardown()
	ch := make(chan error, 1)
	handler := func(ls *localServerSCTP, ln net.Listener) { ls.transponder(ln, ch) }
	if err := ls.buildup(handler); err != nil {
		t.Fatal(err)
	}
	if ls.Listener.Addr().Network() != network {
		t.Fatalf("got %s; want %s", ls.Listener.Addr().Network(), network)
	}

	c, err := Dial(ls.Listener.Addr().Network(), ls.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.LocalAddr().Network() != network || c.RemoteAddr().Network() != network {
		t.Fatalf("got %s->%s; want %s->%s", c.LocalAddr().Network(), c.RemoteAddr().Network(), network, network)
	}
	c.SetDeadline(time.Now().Add(someTimeout))
	c.SetReadDeadline(time.Now().Add(someTimeout))
	c.SetWriteDeadline(time.Now().Add(someTimeout))

	if _, err := c.Write([]byte("CONN AND LISTENER TEST")); err != nil {
		t.Fatal(err)
	}
	rb := make([]byte, 128)
	if _, err := c.Read(rb); err != nil {
		t.Fatal(err)
	}

	for err := range ch {
		t.Error(err)
	}
}
