// Copyright (c) 2024 George Yanev
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

//go:build linux

package sctp

import (
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"unsafe"
)

type SCTPConn struct {
	conn
}

// BindAdd associates additional addresses with an already bound endpoint (i.e. socket).
// If the endpoint supports dynamic address reconfiguration, BindAdd may cause an
// endpoint to send the appropriate message to its peer to change the peer's address lists.
//
// Port number should be absent from the address string.
//
// The outcome of BindAdd and BindRemove is affected by `net.sctp.addip_enable` and
// `net.sctp.addip_noauth_enable` kernel parameters.
func (c *SCTPConn) BindAdd(address string) error {
	if !c.ok() {
		return unix.EINVAL
	}
	laddr, err := resolveSCTPAddr("bindx", c.fd.net, address, nil)
	if err != nil {
		return &net.OpError{Op: "bindx", Net: c.fd.net, Source: nil, Addr: c.fd.laddr.Load(),
			Err: errors.New("add address: " + address + ": " + err.Error())}
	}
	laddr.Port = c.LocalAddr().(*SCTPAddr).Port
	if err = c.BindAddSCTP(laddr); err != nil {
		return err
	}
	return nil
}

func (c *SCTPConn) BindAddSCTP(laddr *SCTPAddr) error {
	if !c.ok() {
		return unix.EINVAL
	}
	if err := c.fd.bind(laddr, _SCTP_SOCKOPT_BINDX_ADD); err != nil {
		return &net.OpError{Op: "bindx", Net: c.fd.net, Source: nil, Addr: c.fd.laddr.Load(),
			Err: errors.New("add address: " + laddr.String() + ": " + err.Error())}
	}
	return nil
}

// BindRemove removes some addresses with which a bound socket is associated.
// If the endpoint supports dynamic address reconfiguration, BindRemove may cause an
// endpoint to send the appropriate message to its peer to change the peer's address lists.
//
// Port number should be absent from the address string.
//
// The outcome of BindAdd and BindRemove is affected by `net.sctp.addip_enable` and
// `net.sctp.addip_noauth_enable` kernel parameters.
func (c *SCTPConn) BindRemove(address string) error {
	if !c.ok() {
		return unix.EINVAL
	}
	laddr, err := resolveSCTPAddr("bindx", c.fd.net, address, nil)
	if err != nil {
		return &net.OpError{Op: "bindx", Net: c.fd.net, Source: nil, Addr: c.fd.laddr.Load(),
			Err: errors.New("remove address: " + address + ": " + err.Error())}
	}
	laddr.Port = c.LocalAddr().(*SCTPAddr).Port
	if err = c.BindRemoveSCTP(laddr); err != nil {
		return err
	}
	return nil
}

func (c *SCTPConn) BindRemoveSCTP(laddr *SCTPAddr) error {
	if !c.ok() {
		return unix.EINVAL
	}
	if err := c.fd.bind(laddr, _SCTP_SOCKOPT_BINDX_REM); err != nil {
		return &net.OpError{Op: "bindx", Net: c.fd.net, Source: nil, Addr: c.fd.laddr.Load(),
			Err: errors.New("remove address: " + laddr.String() + ": " + err.Error())}
	}
	return nil
}

func (c *SCTPConn) ReadMsg(b []byte) (n int, rcvInfo *RcvInfo, recvFlags int, err error) {
	oob := make([]byte, 256)
	return c.ReadMsgExt(b, oob)
}

// ReadMsgExt reads a message from the socket and stores it into 'b'.
// The 'obb' buffer is filled with ancillary data from which the rcvInfo return arg is composed.
//
// If there is no room for the message in b, ReadMsgExt fills b with part
// of the message and clears SCTP_EOR flag in recvFlags. The rest of the message
// should be retrieved using subsequent calls to ReadMsgExt, the last one having
// SCTP_EOR set.
// If there is no room for the ancillary data in obb, ReadMsgExt fills obb with part
// of the ancillary data and sets SCTP_CTRUNC flag in recvFlags.
//
// The message stored in 'b' can be a regular message or a notification(event)
// message. Notifications are returned only if Subscribe has been called prior
// to reading the message. If the message is a notification, the SCTP_NOTIFICATION
// flag will be set in recvFlags.
// A ReadMsgExt call will return only one notification at a time.  Just
// as when reading normal data, it may return part of a notification if
// the buffer passed is not large enough. If a single read is not
// sufficient, recvFlags will have SCTP_EOR unset, indicating the need for further
// reads to complete the notification retrieval.
// The notification message can later be parsed with ParseEvent function
// once a complete message has been obtained.
//
// ReadMsgExt returns:
//
// n: Number of bytes read and stored into b.
// rcvInfo: Information about the received message.
// recvFlags: Received message flags (i.e. SCTP_NOTIFICATION, SCTP_EOR).
// err: Error encountered during reading, if any.
//
// Since os.File is used for integration with the poller, os.ErrClosed
// should be checked instead of net.ErrClosed.
//
// If the basic SCTP functionality meets the caller's needs, the SCTPConn.Read
// function may be used as a simpler alternative.
func (c *SCTPConn) ReadMsgExt(b, oob []byte) (n int, rcvInfo *RcvInfo, recvFlags int, err error) {
	if !c.ok() {
		return 0, nil, 0, unix.EINVAL
	}
	n, rcvInfo, rcvFlags, err := c.fd.readMsg(b, oob)
	if err != nil && err != io.EOF {
		err = &net.OpError{Op: "readMsg", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return n, rcvInfo, rcvFlags, err
}

// WriteMsg is a simplified form of WriteMsgExt
func (c *SCTPConn) WriteMsg(b []byte, info *SndInfo) (int, error) {
	return c.WriteMsgExt(b, info, nil, 0)
}

// WriteMsgExt is used to transmit the data passed in `b` to its peer.
// Different types of ancillary data can be sent and received along
// with user data.  When sending, the ancillary data is used to
// specify the send behavior, such as the SCTP stream number to use
// or the protocol payload identifier (Ppid). These are specified in
// the SndInfo struct, which is optional. If SndInfo is null
// the data is sent on stream number 0 by default.
// If the caller wants to send the message to a specific peer address
// (hence overriding the primary address), it can provide the specific
// address in the `to` argument.
//
// This function call may also be used to terminate an association.  The
// caller provides an SndInfo struct with the Flags field set to
// SCTP_EOF.
//
// WriteMsgExt returns the number of bytes accepted by the kernel or an
// error in case of any.
// Since os.File is used for integration with the poller, os.ErrClosed
// should be checked instead of net.ErrClosed for closure detection.
//
// If the basic SCTP functionality meets the caller's needs, the SCTPConn.Write
// function may be used as a simpler alternative.
func (c *SCTPConn) WriteMsgExt(b []byte, info *SndInfo, to *net.IPAddr, flags int) (int, error) {
	if !c.ok() {
		return 0, unix.EINVAL
	}
	n, err := c.fd.writeMsg(b, info, to, flags)
	if err != nil {
		err = &net.OpError{Op: "writeMsg", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return n, err
}

// Subscribe to one or more of the SCTP event types.
// By default, we do not subscribe to any events.
// Once Subscribe is called, the events are received with
// ReadMsg having SCTP_NOTIFICATION flag set in recvFlags.
func (c *SCTPConn) Subscribe(event ...EventType) error {
	if !c.ok() {
		return unix.EINVAL
	}
	for _, e := range event {
		if err := c.fd.subscribe(e, true); err != nil {
			return err
		}
	}
	return nil
}

// Unsubscribe from one or more of the SCTP event types we have previously subscribed.
func (c *SCTPConn) Unsubscribe(event ...EventType) error {
	if !c.ok() {
		return unix.EINVAL
	}
	for _, e := range event {
		if err := c.fd.subscribe(e, false); err != nil {
			return err
		}
	}
	return nil
}

// RefreshRemoteAddr is called to refresh potentially changed remote peer address.
// I.e. after receiving an SCTP_PEER_ADDR_CHANGE event
func (c *SCTPConn) RefreshRemoteAddr() (*SCTPAddr, error) {
	if !c.ok() {
		return nil, unix.EINVAL
	}
	c.fd.refreshRemoteAddr()
	return c.fd.raddr.Load(), nil
}

// SetNoDelay turns on/off any Nagle-like algorithm. This means that
// packets are generally sent as soon as possible, and no unnecessary
// delays are introduced, at the cost of more packets in the network.
// In particular, not using any Nagle-like algorithm might reduce the
// bundling of small user messages in cases where this would require an
// additional delay.
// Turning this option on disables any Nagle-like algorithm.
func (c *SCTPConn) SetNoDelay(noDelay bool) error {
	if !c.ok() {
		return unix.EINVAL
	}
	if err := c.fd.setNoDelay(noDelay); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return nil
}

// SetDisableFragments turns an on/off flag. If enabled, no SCTP message
// fragmentation will be performed. The effect of enabling this option
// is that if a message being sent exceeds the current Path MTU (PMTU)
// size, the message will not be sent and instead an error will be
// indicated to the user. If this option is disabled (the default),
// then a message exceeding the size of the PMTU will be fragmented and
// reassembled by the peer.
func (c *SCTPConn) SetDisableFragments(disableFragments bool) error {
	if !c.ok() {
		return unix.EINVAL
	}
	if err := c.fd.setDisableFragments(disableFragments); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return nil
}

// WriteBufferSize returns the current socket's  write buffer size in bytes.
func (c *SCTPConn) WriteBufferSize() (int, error) {
	if !c.ok() {
		return 0, unix.EINVAL
	}
	sbSize, err := c.fd.writeBufferSize()
	if err != nil {
		return 0, &net.OpError{Op: "get", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return sbSize, nil
}

// ReadBufferSize returns the current socket's read buffer size in bytes.
func (c *SCTPConn) ReadBufferSize() (int, error) {
	if !c.ok() {
		return 0, unix.EINVAL
	}
	sbSize, err := c.fd.readBufferSize()
	if err != nil {
		return 0, &net.OpError{Op: "get", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return sbSize, nil
}

// SetLinger sets the behavior of Close on a connection which still
// has data waiting to be sent or to be acknowledged.
//
// If sec < 0 (the default), SCTP attempts to close the connection
// gracefully by sending a SHUTDOWN message and finish
// sending/acknowledging the data in the background.
//
// If sec == 0, SCTP discards any unsent or unacknowledged data and
// sends an ABORT chunk.
//
// If sec > 0, the data is sent in the background as with sec < 0.
// The Close() can be blocked for at most sec time. Note that the
// time unit is in seconds, according to POSIX, but might be different
// on specific platforms. If the graceful shutdown phase does not
// finish during this period, Close() will return, but the graceful
// shutdown phase will continue in the system.
func (c *SCTPConn) SetLinger(sec int) error {
	if !c.ok() {
		return unix.EINVAL
	}
	err := c.fd.setLinger(sec)
	if err != nil {
		return &net.OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return nil
}

// CloseRead Disables further receive operations.
// No SCTP protocol action is taken.
// Most callers should just use Close.
//
// After calling CloseWrite or CloseRead, Close should be
// called to close the socket descriptor.
func (c *SCTPConn) CloseRead() error {
	if !c.ok() {
		return unix.EINVAL
	}
	if err := c.fd.closeRead(); err != nil {
		return &net.OpError{Op: "close", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return nil
}

// CloseWrite Disables further send operations, and initiates the SCTP
// shutdown sequence.
// Most callers should just use Close.
//
// The major difference between SCTP and TCP shutdown() is that SCTP
// SHUT_WR (CloseWrite) initiates immediate and full protocol shutdown,
// whereas TCP SHUT_WR causes TCP to go into the half close state.
// SHUT_RD (CloseRead) behaves the same for SCTP as for TCP.
// The purpose of SCTP SHUT_WR is to close the SCTP association while
// still leaving the socket descriptor open. This allows the caller to
// receive back any data that SCTP is unable to deliver and receive event
// notifications.
// After calling CloseWrite or CloseRead, Close should be
// called to close the socket descriptor.
//
// To perform the ABORT operation, an application can use the SetLinger
// function, or SCTP_ABORT flag in SndInfo struct.
func (c *SCTPConn) CloseWrite() error {
	if !c.ok() {
		return unix.EINVAL
	}
	if err := c.fd.closeWrite(); err != nil {
		return &net.OpError{Op: "close", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return nil
}

// Status returns the current status of the SCTP association.
func (c *SCTPConn) Status() (*Status, error) {
	if !c.ok() {
		return nil, unix.EINVAL
	}
	sctpStatus, err := c.fd.status()
	if err != nil {
		return nil, &net.OpError{Op: "get", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return sctpStatus, nil
}

func newSCTPConn(fd *sctpFD) *SCTPConn {
	_ = fd.setNoDelay(true)
	// TODO: manage heartbeat here
	return &SCTPConn{conn{fd: fd}}
}

// Htonui32 does host to network byte order for an uint32
func Htonui32(i uint32) uint32 {
	var res uint32
	p := (*[4]byte)(unsafe.Pointer(&res))
	p[0] = byte(i >> 24)
	p[1] = byte(i >> 16)
	p[2] = byte(i >> 8)
	p[3] = byte(i)
	return res
}

// Ntohui32 does network to host byte order for an uint32
func Ntohui32(i uint32) uint32 {
	p := (*[4]byte)(unsafe.Pointer(&i))
	return uint32(p[0])<<24 + uint32(p[1])<<16 + uint32(p[2])<<8 + uint32(p[3])
}

// Htonui16 does host to network byte order for an uint16
func Htonui16(i uint16) uint16 {
	var res uint16
	p := (*[2]byte)(unsafe.Pointer(&res))
	p[0] = byte(i >> 8)
	p[1] = byte(i)
	return res
}

// Ntohui16 does network to host byte order for an uint16
func Ntohui16(i uint16) uint16 {
	p := (*[2]byte)(unsafe.Pointer(&i))
	return uint16(p[0])<<8 + uint16(p[1])
}
