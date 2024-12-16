// Copyright (c) 2024 George Yanev
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

//go:build linux

package sctp

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"testing"
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
