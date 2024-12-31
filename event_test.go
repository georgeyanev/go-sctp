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
	"unsafe"
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
		if e.Flags() != 0 {
			errorChan <- errors.New("expected flags == 0")
			return
		}
		if e.Type() != SCTP_ASSOC_CHANGE {
			errorChan <- errors.New("expected SCTP_ASSOC_CHANGE")
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
		if rcvInfo.Ppid != 32000 {
			errorChan <- fmt.Errorf("expected Ppid of 32000, got: %d", rcvInfo.Ppid)
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
	_, err = c.(*SCTPConn).WriteMsgExt([]byte("hello"),
		&SndInfo{Ppid: 32000},
		&net.IPAddr{IP: net.ParseIP("127.0.0.1").To4()},
		0)
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
		if e.Flags() != 0 {
			errorChan <- errors.New("expected flags == 0")
			return
		}
		if e.Type() != SCTP_SHUTDOWN_EVENT {
			errorChan <- errors.New("expected SCTP_SHUTDOWN_EVENT")
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
	defer func(ln1 net.Listener) {
		_ = ln1.(*SCTPListener).Unsubscribe(SCTP_ASSOC_CHANGE)
		_ = ln1.Close()
	}(ln1)

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
		if e.Flags() != 0 {
			errorChan <- errors.New("expected flags == 0")
			return
		}
		if e.Type() != SCTP_ADAPTATION_INDICATION {
			errorChan <- errors.New("expected SCTP_ADAPTATION_INDICATION")
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
		n, _, recvFlags, err1 := c.(*SCTPConn).ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		if !bytes.Equal(b[:n], []byte("hello")) {
			errorChan <- errors.New("expected equal 'hello', got: " + string(b[:n]))
			return
		}
		if recvFlags&SCTP_CTRUNC == SCTP_CTRUNC {
			errorChan <- errors.New("expected ancillary data not to be truncated")
			return
		}

		// read EOF
		n, _, _, err1 = c.(*SCTPConn).ReadMsg(b)
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

	_, err = c.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	c1 := c.(*SCTPConn)
	if err = c1.Subscribe(SCTP_SENDER_DRY_EVENT); err != nil {
		t.Fatal(err)
	}

	b := make([]byte, 256)
	n, _, recvFlags, err := c1.ReadMsg(b)
	if err != nil {
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
	if e.Flags() != 0 {
		errorChan <- errors.New("expected flags == 0")
		return
	}
	if e.Type() != SCTP_SENDER_DRY_EVENT {
		errorChan <- errors.New("expected SCTP_SENDER_DRY_EVENT")
		return
	}
	_, ok := e.(*SenderDryEvent)
	if !ok {
		t.Fatal(errors.New("expected SenderDryEvent"))
	}
	if err = c1.Unsubscribe(SCTP_SENDER_DRY_EVENT); err != nil {
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

func TestParseEvent(t *testing.T) {
	i := uint16(1)
	if *(*byte)(unsafe.Pointer(&i)) == 0 {
		t.Skip("skipping on big endian systems")
	}

	e, err := ParseEvent([]byte{})
	if err == nil {
		t.Fatal("expected error")
	}

	var b = []byte{
		2, 128, 0, 0, 148, 0, 0, 0, 2, 0, 178, 41, 127, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 76,
		2, 0, 0}

	// SCTP_PEER_ADDR_CHANGE event
	e, err = ParseEvent(b)
	if err != nil {
		t.Fatal(err)
	}
	if e.Flags() != 0 {
		t.Fatal("expected flags == 0")
	}
	if e.Type() != SCTP_PEER_ADDR_CHANGE {
		t.Fatal("expected SCTP_PEER_ADDR_CHANGE")
	}
	pace, ok := e.(*PeerAddrChangeEvent)
	if !ok {
		t.Fatal(errors.New("expected PeerAddrChangeEvent"))
	}
	if pace.State != SCTP_ADDR_ADDED {
		t.Fatal(errors.New("expected SCTP_ADDR_ADDED"))
	}
	if pace.Addr.String() != "127.0.0.2" {
		t.Fatal(errors.New("expected 127.0.0.2 address to be added"))
	}

	// _SCTP_SEND_FAILED
	b = []byte{3, 128, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err == nil {
		t.Fatal("expected error")
	}

	// SCTP_REMOTE_ERROR
	b = []byte{4, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err != nil {
		t.Fatal(err)
	}
	if e.Flags() != 0 {
		t.Fatal("expected flags == 0")
	}
	if e.Type() != SCTP_REMOTE_ERROR {
		t.Fatal("expected SCTP_REMOTE_ERROR")
	}
	_, ok = e.(*RemoteErrorEvent)
	if !ok {
		t.Fatal(errors.New("expected RemoteErrorEvent"))
	}

	// SCTP_PARTIAL_DELIVERY_EVENT
	b = []byte{6, 128, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err == nil {
		t.Fatal("expected error")
	}

	// SCTP_AUTHENTICATION_EVENT
	b = []byte{8, 128, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err == nil {
		t.Fatal("expected error")
	}

	// SCTP_STREAM_RESET_EVENT
	b = []byte{10, 128, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err == nil {
		t.Fatal("expected error")
	}

	// SCTP_ASSOC_RESET_EVENT
	b = []byte{11, 128, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err == nil {
		t.Fatal("expected error")
	}

	// SCTP_STREAM_CHANGE_EVENT
	b = []byte{12, 128, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err == nil {
		t.Fatal("expected error")
	}

	// SCTP_SEND_FAILED_EVENT
	b = []byte{13, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err != nil {
		t.Fatal(err)
	}
	if e.Flags() != 0 {
		t.Fatal("expected flags == 0")
	}
	if e.Type() != SCTP_SEND_FAILED_EVENT {
		t.Fatal("expected SCTP_SEND_FAILED_EVENT")
	}
	_, ok = e.(*SendFailedEvent)
	if !ok {
		t.Fatal(errors.New("expected SendFailedEvent"))
	}

	// unknown event
	b = []byte{128, 128, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err == nil {
		t.Fatal("expected error")
	}

	// too short events
	b = []byte{1, 128, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err == nil {
		t.Fatal("expected too short event")
	}
	//
	b = []byte{2, 128, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err == nil {
		t.Fatal("expected too short event")
	}
	//
	b = []byte{4, 128, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err == nil {
		t.Fatal("expected too short event")
	}
	//
	b = []byte{5, 128, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err == nil {
		t.Fatal("expected too short event")
	}
	//
	b = []byte{7, 128, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err == nil {
		t.Fatal("expected too short event")
	}
	//
	b = []byte{9, 128, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err == nil {
		t.Fatal("expected too short event")
	}
	//
	b = []byte{13, 128, 0, 0, 0, 0, 0, 0}
	e, err = ParseEvent(b)
	if err == nil {
		t.Fatal("expected too short event")
	}
}
