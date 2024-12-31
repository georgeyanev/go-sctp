// Copyright (c) 2024 George Yanev
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

//go:build linux

package sctp

import (
	"io"
	"log"
	"net"
	"strings"
	"testing"
)

func TestListenerBindAddRemove(t *testing.T) {
	ln1, err := Listen("sctp4", "127.0.0.1/127.0.0.2/127.0.0.3/127.0.0.4:0")
	if err != nil {
		t.Fatal(err)
	}
	ln1SCTP := ln1.(*SCTPListener)
	err = ln1SCTP.BindRemove("127.0.0.2/127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ln1.Addr().String(), "127.0.0.1") ||
		strings.Contains(ln1.Addr().String(), "127.0.0.2") {
		t.Fatal(err)
	}
	err = ln1SCTP.BindAdd("127.0.0.2/127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ln1.Addr().String(), "127.0.0.1") ||
		!strings.Contains(ln1.Addr().String(), "127.0.0.2") {
		t.Fatal(err)
	}
	_ = ln1.Close()

	//
	ln1, err = Listen("sctp", "[::1]/127.0.0.1/127.0.0.2/127.0.0.3/127.0.0.4:0")
	if err != nil {
		t.Fatal(err)
	}
	ln1SCTP = ln1.(*SCTPListener)
	err = ln1SCTP.BindRemove("[::1]/127.0.0.2/127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ln1.Addr().String(), "127.0.0.1") ||
		strings.Contains(ln1.Addr().String(), "127.0.0.2") ||
		strings.Contains(ln1.Addr().String(), "::1") {
		t.Fatal(err)
	}

	err = ln1SCTP.BindAdd("[::1]/127.0.0.2/127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ln1.Addr().String(), "127.0.0.1") ||
		!strings.Contains(ln1.Addr().String(), "127.0.0.2") ||
		!strings.Contains(ln1.Addr().String(), "::1") {
		t.Fatal(err)
	}
	_ = ln1.Close()
}

func TestSCTPConnBindAddRemove(t *testing.T) {
	ln1, err := Listen("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	closeChan := make(chan struct{})
	errorChan := make(chan error)
	go func() {
		c, err1 := ln1.Accept()
		if err1 != nil {
			errorChan <- err1
			return
		}
		defer func(c net.Conn) {
			c.Close()
			close(closeChan)
		}(c)

		b := make([]byte, 256)
		// read EOF
		_, _, _, err1 = c.(*SCTPConn).ReadMsg(b)
		if err1 != nil && err1 != io.EOF {
			errorChan <- err1
			return
		}
	}()

	var d = Dialer{
		LocalAddr: &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IP{127, 0, 0, 1}}}},
	}
	c, err := d.Dial("sctp4", ln1.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Dial: %s ------> %s", c.LocalAddr().String(), c.RemoteAddr().String())
	c1 := c.(*SCTPConn)

	err = c1.BindAdd("127.0.0.2/127.0.0.3")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c1.LocalAddr().String(), "127.0.0.1") ||
		!strings.Contains(c1.LocalAddr().String(), "127.0.0.2") ||
		!strings.Contains(c1.LocalAddr().String(), "127.0.0.3") {
		t.Fatal(err)
	}

	err = c1.BindRemove("127.0.0.1/127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c1.LocalAddr().String(), "127.0.0.1") ||
		strings.Contains(c1.LocalAddr().String(), "127.0.0.2") {
		t.Fatal(err)
	}

	c.Close()
	select {
	case <-closeChan:
	case err = <-errorChan:
		if err != io.EOF {
			t.Fatal(err)
		}
	}
}
