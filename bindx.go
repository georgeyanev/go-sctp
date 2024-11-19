package sctp

import (
	"errors"
	"net"
)

type Binder interface {
	BindAdd(address string) error
	BindAddSCTP(laddr *SCTPAddr) error
	BindRemove(address string) error
	BindRemoveSCTP(laddr *SCTPAddr) error
}

// BindAdd associates additional addresses with an already bound endpoint (i.e. socket).
// If the endpoint supports dynamic address reconfiguration, BindAdd may cause an
// endpoint to send the appropriate message to its peers to change the peers' address lists.
// If this is a listening socket, new accepted associations will be associated with these
// addresses in addition to the already present ones
// Port number should be equal to the already bound port.
func (c *conn) BindAdd(address string) error {
	if err := c.ok(); err != nil {
		return err
	}
	laddr, err := resolveSCTPAddr("bindx", c.net, address, nil)
	if err != nil {
		return &net.OpError{Op: "bindx", Net: c.net, Source: nil, Addr: c.LocalAddr(),
			Err: errors.New("add address: " + address + ": " + err.Error())}
	}
	if err = c.BindAddSCTP(laddr); err != nil {
		return &net.OpError{Op: "bindx", Net: c.net, Source: nil, Addr: c.LocalAddr(),
			Err: errors.New("add address: " + address + ": " + err.Error())}
	}
	return nil
}

func (c *conn) BindAddSCTP(laddr *SCTPAddr) error {
	if err := c.ok(); err != nil {
		return err
	}
	// bind
	if err := c.rawBindAdd(laddr); err != nil {
		return err
	}
	// set local address
	la, err := c.getLocalAddr()
	if err != nil {
		return err
	}
	c.laddr.Store(la)
	return nil
}

// BindRemove remove some addresses with which a bound socket is associated.
// If this is a listening socket, new associations accepted will not be associated with these addresses
// Port number should be equal to the already bound port.
func (c *conn) BindRemove(address string) error {
	if err := c.ok(); err != nil {
		return err
	}
	laddr, err := resolveSCTPAddr("bindx", c.net, address, nil)
	if err != nil {
		return &net.OpError{Op: "bindx", Net: c.net, Source: nil, Addr: c.LocalAddr(),
			Err: errors.New("remove address: " + address + ": " + err.Error())}
	}
	if err = c.BindRemoveSCTP(laddr); err != nil {
		return &net.OpError{Op: "bindx", Net: c.net, Source: nil, Addr: c.LocalAddr(),
			Err: errors.New("remove address: " + address + ": " + err.Error())}
	}
	return nil
}

func (c *conn) BindRemoveSCTP(laddr *SCTPAddr) error {
	if err := c.ok(); err != nil {
		return err
	}
	// bind
	if err := c.rawBindRemove(laddr); err != nil {
		return err
	}
	// set local address
	la, err := c.getLocalAddr()
	if err != nil {
		return err
	}
	c.laddr.Store(la)
	return nil
}
