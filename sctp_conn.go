package sctp

import (
	"errors"
	"io"
	"net"
)

type SCTPConn struct {
	conn
}

// BindAdd associates additional addresses with an already bound endpoint (i.e. socket).
// If the endpoint supports dynamic address reconfiguration, BindAdd may cause an
// endpoint to send the appropriate message to its peers to change the peers' address lists.
func (c *SCTPConn) BindAdd(address string) error {
	if !c.ok() {
		return errEINVAL
	}
	laddr, err := resolveSCTPAddr("bindx", c.fd.net, address, nil)
	if err != nil {
		return &net.OpError{Op: "bindx", Net: c.fd.net, Source: nil, Addr: c.fd.laddr.Load(),
			Err: errors.New("add address: " + address + ": " + err.Error())}
	}
	if err = c.BindAddSCTP(laddr); err != nil {
		return err
	}
	return nil
}

func (c *SCTPConn) BindAddSCTP(laddr *SCTPAddr) error {
	if !c.ok() {
		return errEINVAL
	}
	if err := c.fd.bind(laddr, _SCTP_SOCKOPT_BINDX_ADD); err != nil {
		return &net.OpError{Op: "bindx", Net: c.fd.net, Source: nil, Addr: c.fd.laddr.Load(),
			Err: errors.New("add address: " + laddr.String() + ": " + err.Error())}
	}
	return nil
}

// BindRemove remove some addresses with which a bound socket is associated.
func (c *SCTPConn) BindRemove(address string) error {
	if !c.ok() {
		return errEINVAL
	}
	laddr, err := resolveSCTPAddr("bindx", c.fd.net, address, nil)
	if err != nil {
		return &net.OpError{Op: "bindx", Net: c.fd.net, Source: nil, Addr: c.fd.laddr.Load(),
			Err: errors.New("remove address: " + address + ": " + err.Error())}
	}
	if err = c.BindRemoveSCTP(laddr); err != nil {
		return err
	}
	return nil
}

func (c *SCTPConn) BindRemoveSCTP(laddr *SCTPAddr) error {
	if !c.ok() {
		return errEINVAL
	}
	if err := c.fd.bind(laddr, _SCTP_SOCKOPT_BINDX_REM); err != nil {
		return &net.OpError{Op: "bindx", Net: c.fd.net, Source: nil, Addr: c.fd.laddr.Load(),
			Err: errors.New("remove address: " + laddr.String() + ": " + err.Error())}
	}
	return nil
}

func (c *SCTPConn) ReadMsg(b []byte) (int, *RcvInfo, error) {
	if !c.ok() {
		return 0, nil, errEINVAL
	}
	n, _, err := c.fd.readMsg(b, 0)
	if err != nil && err != io.EOF {
		err = &net.OpError{Op: "readMsg", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return n, nil, err
}

//func (c *Conn) WriteMsgEor(b []byte, eor bool) (int, error) { return 0, nil }

func (c *SCTPConn) WriteMsg(b []byte, info *SndInfo) (int, error) {
	if !c.ok() {
		return 0, errEINVAL
	}
	n, err := c.fd.writeMsg(b, info, nil, 0)
	if err != nil {
		err = &net.OpError{Op: "writeMsg", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return n, err
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
		return errEINVAL
	}
	if err := c.fd.setNoDelay(noDelay); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return nil
}

func (c *SCTPConn) GetNoDelay() (bool, error) {
	if !c.ok() {
		return false, errEINVAL
	}
	b, err := c.fd.getNoDelay()
	if err != nil {
		return false, &net.OpError{Op: "get", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return b, nil
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
		return errEINVAL
	}
	if err := c.fd.setDisableFragments(disableFragments); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return nil
}

func (c *SCTPConn) GetDisableFragments() (bool, error) {
	if !c.ok() {
		return false, errEINVAL
	}
	b, err := c.fd.getDisableFragments()
	if err != nil {
		return false, &net.OpError{Op: "get", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return b, nil
}

func (c *SCTPConn) SetWriteBuffer(bufSize int) error {
	if !c.ok() {
		return errEINVAL
	}
	if err := c.fd.setWriteBuffer(bufSize); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return nil
}

func (c *SCTPConn) GetWriteBuffer() (int, error) {
	if !c.ok() {
		return 0, errEINVAL
	}
	sbSize, err := c.fd.getWriteBuffer()
	if err != nil {
		return 0, &net.OpError{Op: "get", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return sbSize, nil
}

func (c *SCTPConn) SetReadBuffer(bufSize int) error {
	if !c.ok() {
		return errEINVAL
	}
	if err := c.fd.setReadBuffer(bufSize); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return nil
}

func (c *SCTPConn) GetReadBuffer() (int, error) {
	if !c.ok() {
		return 0, errEINVAL
	}
	sbSize, err := c.fd.getReadBuffer()
	if err != nil {
		return 0, &net.OpError{Op: "get", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return sbSize, nil
}

func newSCTPConnNew(fd *sctpFD) *SCTPConn {
	_ = fd.setNoDelay(true)

	// TO DO: set heartbeat disable here or heartbeat interval
	return &SCTPConn{conn{fd: fd}}
}
