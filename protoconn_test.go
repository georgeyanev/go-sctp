// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the GO_LICENSE file.

// This file contains test code from go's net package, tweaked for SCTP where necessary.

package sctp

import (
	"net"
	"testing"
	"time"
)

func TestSCTPConnSpecificMethods(t *testing.T) {
	la, err := ResolveSCTPAddr("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ListenSCTP("sctp4", la)
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan error, 1)
	handler := func(ls *localServerSCTP, ln net.Listener) { ls.transponder(ls.Listener, ch) }
	ls := (&streamListener{Listener: ln}).newLocalServerSCTP()
	defer ls.teardown()
	if err := ls.buildup(handler); err != nil {
		t.Fatal(err)
	}

	ra, err := ResolveSCTPAddr("sctp4", ls.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := DialSCTP("sctp4", nil, ra)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	//c.SetKeepAlive(false) // TODO: revisit when managing heartbeats is implemented
	//c.SetKeepAlivePeriod(3 * time.Second)
	c.SetLinger(0)
	c.SetNoDelay(false)
	c.LocalAddr()
	c.RemoteAddr()
	c.SetDeadline(time.Now().Add(someTimeout))
	c.SetReadDeadline(time.Now().Add(someTimeout))
	c.SetWriteDeadline(time.Now().Add(someTimeout))

	if _, err := c.Write([]byte("SCTP CONN TEST")); err != nil {
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
