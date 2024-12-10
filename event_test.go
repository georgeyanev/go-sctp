// Copyright (c) 2024 George Yanev
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

//go:build linux

package sctp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"testing"
)

// Test AssocChange even
func TestAssocChangeEvent(t *testing.T) {
	ln1, err := Listen("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	err = ln1.(*SCTPListener).Subscribe(SCTP_ASSOC_CHANGE)
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

		c1 := c.(*SCTPConn)

		b := make([]byte, 256)

		// receive AssocChange event with SCTP_COMM_UP state
		n, rcvInfo, recvFlags, err1 := c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		if (recvFlags & SCTP_NOTIFICATION) != SCTP_NOTIFICATION {
			errorChan <- errors.New("expected SCTP_ASSOC_CHANGE event")
			return
		}
		if (recvFlags & SCTP_EOR) != SCTP_EOR {
			errorChan <- errors.New("expected whole message")
			return
		}
		if rcvInfo != nil {
			errorChan <- errors.New("expected nil rcvInfo")
			return
		}

		e, err1 := ParseEvent(b[:n])
		if err1 != nil {
			errorChan <- err1
			return
		}

		ace, ok := e.(*AssocChangeEvent)
		if !ok {
			errorChan <- errors.New("expected AssocChangeEvent")
			return
		}
		if ace.State != SCTP_COMM_UP {
			errorChan <- errors.New("expected SCTP_COMM_UP")
			return
		}

		// receive data
		n, rcvInfo, recvFlags, err1 = c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		if (recvFlags & SCTP_NOTIFICATION) == SCTP_NOTIFICATION {
			errorChan <- errors.New("expected data message")
			return
		}
		if (recvFlags & SCTP_EOR) != SCTP_EOR {
			errorChan <- errors.New("expected whole message")
			return
		}
		if rcvInfo == nil {
			errorChan <- errors.New("expected non-nil rcvInfo")
			return
		}
		if !bytes.Equal(b[:n], []byte("hello")) {
			errorChan <- errors.New("expected 'hello'")
			return
		}

		// receive AssocChange event with SCTP_SHUTDOWN_COMP state
		n, rcvInfo, recvFlags, err1 = c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		if (recvFlags & SCTP_NOTIFICATION) != SCTP_NOTIFICATION {
			errorChan <- errors.New("expected SCTP_ASSOC_CHANGE event")
			return
		}
		if (recvFlags & SCTP_EOR) != SCTP_EOR {
			errorChan <- errors.New("expected whole message")
			return
		}
		if rcvInfo != nil {
			errorChan <- errors.New("expected nil rcvInfo")
			return
		}

		e, err1 = ParseEvent(b[:n])
		if err1 != nil {
			errorChan <- err1
			return
		}

		ace, ok = e.(*AssocChangeEvent)
		if !ok {
			errorChan <- errors.New("expected AssocChangeEvent")
			return
		}
		if ace.State != SCTP_SHUTDOWN_COMP {
			errorChan <- errors.New("expected SCTP_SHUTDOWN_COMP")
			return
		}

		// subsequent reads from association should return EOF
		n, rcvInfo, recvFlags, err1 = c1.ReadMsg(b)
		if err1 == nil || err1 != io.EOF {
			errorChan <- errors.New("expected EOF")
			return
		}
	}()

	c, err := Dial("sctp4", ln1.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	_, err = c.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	select {
	case <-closeChan:
	case err := <-errorChan:
		if err != io.EOF {
			t.Fatal(err)
		}
	}
}

// For this test to work, the kernel parameters `net.sctp.addip_enable`
// and `net.sctp.addip_noauth_enable` must be set to 1.
func TestPeerAddrChangeEvent(t *testing.T) {
	t.Skip("Comment this after setting appropriate kernel params to execute the test")
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

		c1 := c.(*SCTPConn)
		err1 = c1.Subscribe(SCTP_PEER_ADDR_CHANGE)
		if err1 != nil {
			errorChan <- err1
			return
		}

		b := make([]byte, 256)

		// receive data
		n, _, recvFlags, err1 := c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		c1.RefreshRemoteAddr()
		if (recvFlags & SCTP_NOTIFICATION) == SCTP_NOTIFICATION {
			errorChan <- errors.New("expected data message")
			return
		}
		if (recvFlags & SCTP_EOR) != SCTP_EOR {
			errorChan <- errors.New("expected whole message")
			return
		}
		if !bytes.Equal(b[:n], []byte("hello")) {
			errorChan <- errors.New("expected equal 'hello', got: " + string(b[:n]))
			return
		}
		_, err1 = c1.Write([]byte("yes"))
		if err1 != nil {
			errorChan <- err1
			return
		}

		// receive peer addr change event
		c1.RefreshRemoteAddr()
		n, _, recvFlags, err1 = c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}

		if (recvFlags & SCTP_NOTIFICATION) != SCTP_NOTIFICATION {
			errorChan <- errors.New("expected SCTP_PEER_ADDR_CHANGE event")
			return
		}
		if (recvFlags & SCTP_EOR) != SCTP_EOR {
			errorChan <- errors.New("expected whole message")
			return
		}

		e, err1 := ParseEvent(b[:n])
		if err1 != nil {
			errorChan <- err1
			return
		}

		pace, ok := e.(*PeerAddrChangeEvent)
		if !ok {
			errorChan <- errors.New("expected PeerAddrChangeEvent")
			return
		}
		if pace.State != SCTP_ADDR_ADDED {
			errorChan <- errors.New("expected SCTP_ADDR_ADDED")
			return
		}
		if pace.Addr.String() != "127.0.0.2" {
			errorChan <- errors.New("expected 127.0.0.2 address to be added")
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
	_, err = c.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 8)
	n, err1 := c.Read(b)
	if err1 != nil {
		t.Fatal(err1)
	}
	if !bytes.Equal(b[:n], []byte("yes")) {
		errorChan <- errors.New("expected equal 'yes', got: " + string(b[:n]))
		return
	}

	err = c.(*SCTPConn).BindAdd("127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-closeChan:
	case err = <-errorChan:
		if err != io.EOF {
			t.Fatal(err)
		}
	}
	c.Close()
}

func TestShutdownEvent(t *testing.T) {
	ln1, err := Listen("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	err = ln1.(*SCTPListener).Subscribe(SCTP_REMOTE_ERROR, SCTP_SHUTDOWN_EVENT)
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

		c1 := c.(*SCTPConn)

		b := make([]byte, 256)

		// read data
		n, _, recvFlags, err1 := c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		if (recvFlags & SCTP_NOTIFICATION) == SCTP_NOTIFICATION {
			errorChan <- errors.New("expected data message")
			return
		}
		if (recvFlags & SCTP_EOR) != SCTP_EOR {
			errorChan <- errors.New("expected whole message")
			return
		}
		if !bytes.Equal(b[:n], []byte("hello")) {
			errorChan <- errors.New("expected equal 'hello', got: " + string(b[:n]))
			return
		}

		// read shutdown event
		n, _, recvFlags, err1 = c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}

		if (recvFlags & SCTP_NOTIFICATION) != SCTP_NOTIFICATION {
			errorChan <- errors.New("expected SCTP_ADAPTATION_INDICATION event")
			return
		}
		if (recvFlags & SCTP_EOR) != SCTP_EOR {
			errorChan <- errors.New("expected whole message")
			return
		}

		e, err1 := ParseEvent(b[:n])
		if err1 != nil {
			errorChan <- err1
			return
		}

		_, ok := e.(*ShutdownEvent)
		if !ok {
			errorChan <- errors.New("expected ShutdownEvent")
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
	_, err = c.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	c.Close() // sends SCTP_SHUTDOWN_EVENT
	select {
	case <-closeChan:
	case err = <-errorChan:
		if err != io.EOF {
			t.Fatal(err)
		}
	}
}

// Tweak close to send abort. Then on peer expect SCTP_ASSOC_CHANGE event
// with SCTP_COMM_LOST state and the Abort chunk present in AssocChangeEvent.Info
func TestAbort(t *testing.T) {
	ln1, err := Listen("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err = ln1.(*SCTPListener).Subscribe(SCTP_ASSOC_CHANGE); err != nil {
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

		c1 := c.(*SCTPConn)

		b := make([]byte, 256)

		// receive data
		for {
			n, _, recvFlags, err1 := c1.ReadMsg(b)
			if err1 != nil {
				errorChan <- err1
				return
			}
			if (recvFlags & SCTP_NOTIFICATION) == SCTP_NOTIFICATION {
				e, err1 := ParseEvent(b[:n])
				if err1 != nil {
					errorChan <- err1
					return
				}
				log.Printf("Notification parsed: %T: %v", e, e)
				ace, ok := e.(*AssocChangeEvent)
				if !ok {
					errorChan <- errors.New("expected AssocChangeEvent")
					return
				}
				if ace.State == SCTP_COMM_LOST && len(ace.Info) > 0 {
					return
				}
			} else {
				log.Printf("Data is received: %s", string(b[:n]))
			}
		}
	}()

	var d = Dialer{
		LocalAddr: &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IP{127, 0, 0, 1}}}},
	}
	c, err := d.Dial("sctp4", ln1.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	// We want Close to cause Abort
	if err = c.(*SCTPConn).SetLinger(0); err != nil {
		t.Fatal(err)
	}
	log.Printf("Dial: %s ------> %s", c.LocalAddr().String(), c.RemoteAddr().String())
	_, err = c.Write([]byte("hello"))
	if err != nil {
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

func TestAdaptationEvent(t *testing.T) {
	ln1, err := Listen("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	if err = ln1.(*SCTPListener).Subscribe(SCTP_ADAPTATION_INDICATION); err != nil {
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
		c1 := c.(*SCTPConn)

		// receive adaptation event data
		n, _, recvFlags, err1 := c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}

		if (recvFlags & SCTP_NOTIFICATION) != SCTP_NOTIFICATION {
			errorChan <- errors.New("expected SCTP_ADAPTATION_INDICATION event")
			return
		}
		if (recvFlags & SCTP_EOR) != SCTP_EOR {
			errorChan <- errors.New("expected whole message")
			return
		}

		e, err1 := ParseEvent(b[:n])
		if err1 != nil {
			errorChan <- err1
			return
		}

		ae, ok := e.(*AdaptationEvent)
		if !ok {
			errorChan <- errors.New("expected AdaptationEvent")
			return
		}
		if ae.AdaptationInd != 0x01020304 {
			errorChan <- errors.New(fmt.Sprintf("unexpected AdaptationInd: %d, expected 0x01020304", ae.AdaptationInd))
			return
		}

		// read data
		n, _, recvFlags, err1 = c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		if (recvFlags & SCTP_NOTIFICATION) == SCTP_NOTIFICATION {
			errorChan <- errors.New("expected data message")
			return
		}
		if (recvFlags & SCTP_EOR) != SCTP_EOR {
			errorChan <- errors.New("expected whole message")
			return
		}
		if !bytes.Equal(b[:n], []byte("hello")) {
			errorChan <- errors.New("expected equal 'hello', got: " + string(b[:n]))
			return
		}

	}()

	var d = Dialer{
		LocalAddr: &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IP{127, 0, 0, 1}}}},
		InitOptions: InitOptions{
			AdaptationIndicationEnabled: true,
			AdaptationIndication:        0x01020304,
		},
	}
	c, err := d.Dial("sctp4", ln1.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Dial: %s ------> %s", c.LocalAddr().String(), c.RemoteAddr().String())
	_, err = c.Write([]byte("hello"))
	if err != nil {
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

func TestSenderDryEvent(t *testing.T) {
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

		// read data
		n, _, _, err1 := c.(*SCTPConn).ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		if !bytes.Equal(b[:n], []byte("hello")) {
			errorChan <- errors.New("expected equal 'hello', got: " + string(b[:n]))
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

	_, err = c.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	c1 := c.(*SCTPConn)
	if err = c1.Subscribe(SCTP_SENDER_DRY_EVENT); err != nil {
		t.Fatal(err)
	}

	b := make([]byte, 256)
	n, _, recvFlags, err1 := c1.ReadMsg(b)
	if err1 != nil {
		t.Fatal(err)
	}

	if (recvFlags & SCTP_NOTIFICATION) != SCTP_NOTIFICATION {
		t.Fatal(errors.New("expected SCTP_SENDER_DRY_EVENT event"))
	}
	if (recvFlags & SCTP_EOR) != SCTP_EOR {
		t.Fatal(errors.New("expected whole message"))
	}

	e, err1 := ParseEvent(b[:n])
	if err1 != nil {
		t.Fatal(err)
	}

	_, ok := e.(*SenderDryEvent)
	if !ok {
		t.Fatal(errors.New("expected SenderDryEvent"))
	}

	c.Close() // sends SCTP_SHUTDOWN_EVENT
	select {
	case <-closeChan:
	case err = <-errorChan:
		if err != io.EOF {
			t.Fatal(err)
		}
	}
}
