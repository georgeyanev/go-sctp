package sctp

import (
	"errors"
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
	if err := c.fd.bind(laddr, SCTP_SOCKOPT_BINDX_ADD); err != nil {
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
	if err := c.fd.bind(laddr, SCTP_SOCKOPT_BINDX_REM); err != nil {
		return &net.OpError{Op: "bindx", Net: c.fd.net, Source: nil, Addr: c.fd.laddr.Load(),
			Err: errors.New("remove address: " + laddr.String() + ": " + err.Error())}
	}
	return nil
}

func (c *SCTPConn) ReadMsg(b []byte) (int, bool, error) { return 0, true, nil }

//func (c *Conn) WriteMsgEor(b []byte, eor bool) (int, error) { return 0, nil }

func (c *SCTPConn) WriteMsg(b []byte) (int, error) { return 0, nil }

func newSCTPConnNew(fd *sctpFD) *SCTPConn {
	_ = fd.setNoDelay(true)

	// TO DO: set heartbeat disable here or heartbeat interval
	return &SCTPConn{conn{fd: fd}}
}
