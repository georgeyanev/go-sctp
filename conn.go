package sctp

import (
	"io"
	"net"
	"syscall"
	"time"
)

// TODO: all names with suffix New should replace the old names, and the old names should be deprecated/removed
type connNew struct {
	fd *sctpFD
}

func (c *connNew) Read(b []byte) (int, error) {
	if !c.ok() {
		return 0, errEINVAL
	}
	n, err := c.fd.f.Read(b)
	if err != nil && err != io.EOF {
		err = &net.OpError{Op: "read", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return n, err
}

func (c *connNew) Write(b []byte) (int, error) {
	if !c.ok() {
		return 0, errEINVAL
	}
	n, err := c.fd.f.Write(b)
	if err != nil {
		err = &net.OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return n, err
}

func (c *connNew) SetDeadline(t time.Time) error {
	if !c.ok() {
		return errEINVAL
	}
	if err := c.fd.f.SetDeadline(t); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.net, Source: nil, Addr: c.fd.laddr.Load(), Err: err}
	}
	return nil
}

func (c *connNew) SetReadDeadline(t time.Time) error {
	if !c.ok() {
		return errEINVAL
	}
	if err := c.fd.f.SetReadDeadline(t); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.net, Source: nil, Addr: c.fd.laddr.Load(), Err: err}
	}
	return nil
}

func (c *connNew) SetWriteDeadline(t time.Time) error {
	if !c.ok() {
		return errEINVAL
	}
	if err := c.fd.f.SetWriteDeadline(t); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.net, Source: nil, Addr: c.fd.laddr.Load(), Err: err}
	}
	return nil
}

func (c *connNew) Close() error {
	if !c.ok() {
		return syscall.EINVAL
	}
	err := c.fd.close()
	if err != nil {
		err = &net.OpError{Op: "close", Net: c.fd.net, Source: c.fd.laddr.Load(), Addr: c.fd.raddr.Load(), Err: err}
	}
	return err
}

func (c *connNew) LocalAddr() net.Addr {
	if !c.ok() {
		return nil
	}
	return c.fd.laddr.Load()
}

func (c *connNew) RemoteAddr() net.Addr {
	if !c.ok() {
		return nil
	}
	return c.fd.raddr.Load()
}

// TODO: write SCTP specific functions, i.e. specifying EOF upon return, specifying input/output stream etc.
// bool is EOR

func (c *connNew) ok() bool { return c != nil && c.fd != nil }
