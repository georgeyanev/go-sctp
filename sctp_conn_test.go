// Copyright (c) 2024 George Yanev
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

//go:build linux

package sctp

import (
	"bytes"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPartialRead(t *testing.T) {
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

		b := make([]byte, 1)

		// receive first data byte
		n, rcvInfo, recvFlags, err1 := c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		if (recvFlags & SCTP_EOR) == SCTP_EOR {
			errorChan <- errors.New("expected partial message")
			return
		}
		if rcvInfo == nil {
			errorChan <- errors.New("expected non-nil rcvInfo")
			return
		}
		if !bytes.Equal(b[:n], []byte("1")) {
			errorChan <- errors.New("expected '1'")
			return
		}
		// receive second data byte
		n, rcvInfo, recvFlags, err1 = c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		if (recvFlags & SCTP_EOR) == SCTP_EOR {
			errorChan <- errors.New("expected partial message")
			return
		}
		if rcvInfo == nil {
			errorChan <- errors.New("expected non-nil rcvInfo")
			return
		}
		if !bytes.Equal(b[:n], []byte("2")) {
			errorChan <- errors.New("expected '2'")
			return
		}
		// receive third data byte
		n, rcvInfo, recvFlags, err1 = c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		if (recvFlags & SCTP_EOR) != SCTP_EOR {
			errorChan <- errors.New("expected end of message")
			return
		}
		if rcvInfo == nil {
			errorChan <- errors.New("expected non-nil rcvInfo")
			return
		}
		if !bytes.Equal(b[:n], []byte("3")) {
			errorChan <- errors.New("expected '3'")
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
	_, err = c.Write([]byte("123"))
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
func TestSCTPStatus(t *testing.T) {
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
		sctpStatus, err1 := c1.Status()
		if err1 != nil {
			errorChan <- err1
		}
		// remote ostreams are 11, ours in are 10, remote Instreams are 9, ours out are 10
		if sctpStatus.InStreams != 10 || sctpStatus.OutStreams != 9 {
			errorChan <- errors.New("expected 10 inStreams and 9 outStreams")
		}
	}()
	d := Dialer{
		InitOptions: InitOptions{
			NumOstreams:  11,
			MaxInstreams: 9,
		},
	}
	c, err := d.Dial("sctp4", ln1.Addr().String())
	if err != nil {
		log.Fatal(err)
	}

	select {
	case <-closeChan:
		c.Close()
	case err := <-errorChan:
		c.Close()
		if err != io.EOF {
			t.Fatal(err)
		}
	}
}

func TestSockOpt(t *testing.T) {
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

	if err = c1.SetDisableFragments(true); err != nil {
		t.Fatal(err)
	}

	buffer, err := c1.ReadBufferSize()
	if err != nil {
		t.Fatal(err)
	}
	if buffer <= 0 {
		t.Fatal(errors.New("expected non-zero read buffer size"))
	}

	buffer, err = c1.WriteBufferSize()
	if err != nil {
		t.Fatal(err)
	}
	if buffer <= 0 {
		t.Fatal(errors.New("expected non-zero write buffer size"))
	}

	if _, err = c1.RefreshRemoteAddr(); err != nil {
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

func TestSCTPConnErrors(t *testing.T) {
	c := SCTPConn{conn{}}
	var err error

	err = c.BindAdd("127.0.0.2/127.0.0.3")
	checkErr(t, err, unix.EINVAL)
	err = c.BindAddSCTP(nil)
	checkErr(t, err, unix.EINVAL)
	err = c.BindRemove("127.0.0.2/127.0.0.3")
	checkErr(t, err, unix.EINVAL)
	err = c.BindRemoveSCTP(nil)
	checkErr(t, err, unix.EINVAL)
	_, _, _, err = c.ReadMsg([]byte{})
	checkErr(t, err, unix.EINVAL)
	_, err = c.WriteMsg(nil, nil)
	checkErr(t, err, unix.EINVAL)
	err = c.Subscribe()
	checkErr(t, err, unix.EINVAL)
	err = c.Unsubscribe()
	checkErr(t, err, unix.EINVAL)
	_, err = c.RefreshRemoteAddr()
	checkErr(t, err, unix.EINVAL)
	err = c.SetNoDelay(true)
	checkErr(t, err, unix.EINVAL)
	err = c.SetDisableFragments(true)
	checkErr(t, err, unix.EINVAL)
	_, err = c.WriteBufferSize()
	checkErr(t, err, unix.EINVAL)
	_, err = c.ReadBufferSize()
	checkErr(t, err, unix.EINVAL)
	err = c.SetLinger(0)
	checkErr(t, err, unix.EINVAL)
	err = c.CloseRead()
	checkErr(t, err, unix.EINVAL)
	err = c.CloseWrite()
	checkErr(t, err, unix.EINVAL)
	_, err = c.Status()
	checkErr(t, err, unix.EINVAL)
	// conn
	_, err = c.Read([]byte{})
	checkErr(t, err, unix.EINVAL)
	_, err = c.Write(nil)
	checkErr(t, err, unix.EINVAL)
	err = c.SetDeadline(time.Time{})
	checkErr(t, err, unix.EINVAL)
	err = c.SetReadDeadline(time.Time{})
	checkErr(t, err, unix.EINVAL)
	err = c.SetWriteDeadline(time.Time{})
	checkErr(t, err, unix.EINVAL)
	err = c.Close()
	checkErr(t, err, unix.EINVAL)
	c.LocalAddr()
	c.RemoteAddr()

	//
	c1 := SCTPConn{conn{fd: &sctpFD{}}}
	err = c1.BindAdd("127.0.0.2")
	checkOpErr(t, err)
	err = c1.BindAddSCTP(nil)
	checkOpErr(t, err)
	err = c1.BindRemove("127.0.0.2")
	checkOpErr(t, err)
	err = c1.BindRemoveSCTP(nil)
	checkOpErr(t, err)
	err = c1.Subscribe(SCTP_SENDER_DRY_EVENT)
	checkErr(t, err, unix.EINVAL)
	err = c1.Unsubscribe(SCTP_SENDER_DRY_EVENT)
	checkErr(t, err, unix.EINVAL)
	err = c1.SetNoDelay(true)
	checkErr(t, err, unix.EINVAL)
	err = c1.SetDisableFragments(true)
	checkErr(t, err, unix.EINVAL)
	_, err = c1.WriteBufferSize()
	checkErr(t, err, unix.EINVAL)
	_, err = c1.ReadBufferSize()
	checkErr(t, err, unix.EINVAL)
	err = c1.SetLinger(0)
	checkErr(t, err, unix.EINVAL)
	err = c1.CloseRead()
	checkErr(t, err, unix.EINVAL)
	err = c1.CloseWrite()
	checkErr(t, err, unix.EINVAL)
	_, err = c1.Status()
	checkErr(t, err, unix.EINVAL)
	_, err = c1.fd.accept()
	checkErr(t, err, unix.EINVAL)
	_, err = c1.fd.writeMsg(nil, nil, nil, 0)
	checkErr(t, err, unix.EINVAL)
	_, _, _, err = c1.fd.readMsg(nil, nil)
	checkErr(t, err, unix.EINVAL)
	c1.fd.refreshLocalAddr()
	c1.fd.refreshRemoteAddr()
	err = c1.fd.init(-1)
	if err == nil {
		t.Fatal("expected error, got none")
	}
	_, err = c1.fd.retrieveLocalAddr()
	checkErr(t, err, unix.EINVAL)
	_, err = c1.fd.retrieveRemoteAddr()
	checkErr(t, err, unix.EINVAL)
	err = c1.fd.close()
	checkErr(t, err, unix.EINVAL)

}

func checkErr(t *testing.T, err error, errExpected error) {
	if !errors.Is(err, errExpected) {
		t.Fatal(err)
	}
}

func checkOpErr(t *testing.T, err error) {
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatal(err)
	}
}

func TestHtonui32Ntohui32(t *testing.T) {
	var a uint32 = 0x01020304
	b := Htonui32(Ntohui32(a))
	if a != b {
		t.Fatalf("Htonui32(Ntohui32(a)) = %d, want %d", b, a)
	}
	b = Ntohui32(Htonui32(a))
	if a != b {
		t.Fatalf("Htonui32(Ntohui32(a)) = %d, want %d", b, a)
	}
}

func TestHtonui16Ntohui16(t *testing.T) {
	var a uint16 = 0x0102
	b := Htonui16(Ntohui16(a))
	if a != b {
		t.Fatalf("Htonui16(Ntohui16(a)) = %d, want %d", b, a)
	}
	b = Ntohui16(Htonui16(a))
	if a != b {
		t.Fatalf("Htonui16(Ntohui16(a)) = %d, want %d", b, a)
	}
}
