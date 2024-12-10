// Copyright (c) 2024 George Yanev
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

//go:build linux

package sctp

import (
	"golang.org/x/sys/unix"
	"io"
	"net"
	"syscall"
	"time"
)

type conn struct {
	fd *sctpFD
}

// Read receives data from the peer of an SCTP endpoint.
// It gives access to only basic SCTP protocol
// features.  If either peer in the association uses multiple streams,
// or sends unordered data, this call will usually be inadequate and may
// deliver the data in unpredictable ways.
// Read return data from any stream, but the caller
// cannot distinguish the different streams. This may result in data
// seeming to arrive out of order. Similarly, if a DATA chunk is sent
// unordered, Read() provide no indication.
//
// If the buffer supplied is not large enough to hold a
// complete SCTP message, the Read call acts like a stream socket and
// returns as much data as will fit in the buffer.
//
// Read cannot distinguish message boundaries (i.e., there is no way
// to observe the MSG_EOR flag to detect partial delivery)
//
// If you want specific SCTP features, use the ReadMsg() functions.
func (c *conn) Read(b []byte) (int, error) {
	if !c.ok() {
		return 0, unix.EINVAL
	}
	n, err := c.fd.f.Read(b)
	if err != nil && err != io.EOF {
		err = &net.OpError{Op: "read", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return n, err
}

// Write transmit data to the peer of an SCTP endpoint.
// It gives access to only basic SCTP protocol features.
// SCTP has the concept of multiple streams in one association.
// Write do not allow the caller to specify on which stream a
// message should be sent. The system uses stream 0 as the default
// stream.
// SCTP is message based. The msg buffer above in Write
// is considered to be a single message.
//
// Sending a message using Write is atomic.
// The maximum size of the buffer passed to Write is limited by
// the write buffer size of the socket.
// See: https://datatracker.ietf.org/doc/html/rfc6458#page-67
//
// If you want specific SCTP features, use the WriteMsg() functions.
func (c *conn) Write(b []byte) (int, error) {
	if !c.ok() {
		return 0, unix.EINVAL
	}
	n, err := c.fd.f.Write(b)
	if err != nil {
		err = &net.OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return n, err
}

// SetDeadline sets both the read and write deadlines associated with the Conn.
func (c *conn) SetDeadline(t time.Time) error {
	if !c.ok() {
		return unix.EINVAL
	}
	if err := c.fd.f.SetDeadline(t); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.net, Source: nil, Addr: c.fd.laddr.Load(), Err: err}
	}
	return nil
}

// SetReadDeadline sets the read deadline associated with the Conn.
func (c *conn) SetReadDeadline(t time.Time) error {
	if !c.ok() {
		return unix.EINVAL
	}
	if err := c.fd.f.SetReadDeadline(t); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.net, Source: nil, Addr: c.fd.laddr.Load(), Err: err}
	}
	return nil
}

// SetWriteDeadline sets the write deadline associated with the Conn.
func (c *conn) SetWriteDeadline(t time.Time) error {
	if !c.ok() {
		return unix.EINVAL
	}
	if err := c.fd.f.SetWriteDeadline(t); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.net, Source: nil, Addr: c.fd.laddr.Load(), Err: err}
	}
	return nil
}

// Close closes the association.
// By default, a graceful close is performed and
// a SHUTDOWN message is sent to the peer.
// If different behaviour is desired (i.e. immediate
// close and sending ABORT chunk), use the SCTPConn.SetLinger
// function.
// Also, different close behaviour can be achieved by using
// the SndInfo flags appropriately.
func (c *conn) Close() error {
	if !c.ok() {
		return syscall.EINVAL
	}
	err := c.fd.close()
	if err != nil {
		err = &net.OpError{Op: "close", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return err
}

func (c *conn) LocalAddr() net.Addr {
	if !c.ok() {
		return nil
	}
	return c.fd.laddr.Load()
}

func (c *conn) RemoteAddr() net.Addr {
	if !c.ok() {
		return nil
	}
	return c.fd.raddr.Load()
}

func (c *conn) ok() bool { return c != nil && c.fd != nil }
