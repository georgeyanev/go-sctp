// Copyright (c) 2024 George Yanev
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

//go:build linux

package sctp

import (
	"context"
	"net"
	"syscall"
	"time"
)

// A Dialer contains options for connecting to an address.
type Dialer struct {
	// Timeout is the maximum amount of time a dial will wait for
	// a connect to complete. If Deadline is also set, it may fail
	// earlier.
	//
	// The default is no timeout.
	//
	// With or without a timeout, the operating system may impose
	// its own earlier timeout.
	Timeout time.Duration

	// Deadline is the absolute point in time after which dials
	// will fail. If Timeout is set, it may fail earlier.
	// Zero means no deadline, or dependent on the operating system
	// as with the Timeout option.
	Deadline time.Time

	// LocalAddr is the local address to use when dialing an address.
	// If nil, a local address is automatically chosen.
	LocalAddr *SCTPAddr

	// If Control is not nil, it is called after creating the network
	// connection but before actually dialing.
	//
	// Network and address parameters passed to Control function are not
	// necessarily the ones passed to Dial. For example, passing "sctp" to Dial
	// will cause the Control function to be called with "sctp4" or "sctp6".
	//
	// Control is ignored if ControlContext is not nil.
	Control func(network, address string, c syscall.RawConn) error

	// If ControlContext is not nil, it is called after creating the network
	// connection but before actually dialing.
	//
	// Network and address parameters passed to ControlContext function are not
	// necessarily the ones passed to Dial. For example, passing "sctp" to Dial
	// will cause the ControlContext function to be called with "sctp4" or "sctp6".
	//
	// If ControlContext is not nil, Control is ignored.
	ControlContext func(ctx context.Context, network, address string, c syscall.RawConn) error

	// provides information for initializing new SCTP associations
	InitOptions InitOptions
}

// Dial connects to the address on the named network.
//
// Known networks are "sctp", "sctp4" (IPv4-only), "sctp6" (IPv6-only),
//
// The address has the form "host:port" for single-homing or
// host1/host2/host3:port for multi-homing (the number of hosts/IPs are not limited)
// The host must be a literal IP address, or a host name that can be
// resolved to IP addresses (which is not recommended,
// because at most one of the host's IP addresses will be used).
// The port must be a literal port number or a service name.
// If the host is a literal IPv6 address it must be enclosed in square
// brackets, as in "[2001:db8::1]:80" or "[fe80::1%zone]:80".
// The zone specifies the scope of the literal IPv6 address as defined
// in RFC 4007.
//
// Examples:
//
//	Dial("sctp", "golang.org:http")
//	Dial("sctp", "192.0.2.1/192.0.2.2:http")
//	Dial("sctp", "198.51.100.1/[2001:db8::1]:8000")
//	Dial("sctp", "[fe80::1%lo0]/[::1]:5333")
//	Dial("sctp", ":8000")
//
// If the host is empty or a literal unspecified IP address, as
// in ":80", "0.0.0.0:80" or "[::]:80" the local system is
// assumed.
func Dial(network, address string) (net.Conn, error) {
	var d Dialer
	return d.Dial(network, address)
}

// DialSCTP acts like [Dial] taking SCTP addresses and returning a SCTPConn.
//
// If laddr is nil, a local address is automatically chosen.
// If raddr is nil or an unspecified IP address, the local system is assumed.
func DialSCTP(network string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	var d Dialer
	d.LocalAddr = laddr
	return d.DialSCTP(network, raddr)
}

// Dial connects to the address on the named network.
//
// See func Dial for a description of the network and address
// parameters.
//
// Dial uses [context.Background] internally; to specify the context, use
// [Dialer.DialContext].
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext connects to the address on the named network using the provided context.
// The context is not used in resolving host to IP addresses (if there is any).
//
// The provided Context must be non-nil. If the context expires before
// the connection is complete, an error is returned. Once successfully
// connected, any expiration of the context will not affect the
// connection.
func (d *Dialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	// resolve with no context
	raddr, err := resolveSCTPAddr("dial", network, address, d.LocalAddr)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Source: nil, Addr: nil, Err: err}
	}
	return d.DialSCTPContext(ctx, network, raddr)
}

func (d *Dialer) DialSCTP(network string, raddr *SCTPAddr) (*SCTPConn, error) {
	return d.DialSCTPContext(context.Background(), network, raddr)
}

// DialSCTPContext acts like DialContext taking SCTP addresses and returning a SCTPConn.
func (d *Dialer) DialSCTPContext(ctx context.Context, network string, raddr *SCTPAddr) (*SCTPConn, error) {
	if ctx == nil {
		panic("nil context")
	}

	switch network {
	case "sctp", "sctp4", "sctp6":
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Source: nil, Addr: raddr.opAddr(), Err: net.UnknownNetworkError(network)}
	}

	deadline := d.deadline(ctx, time.Now())
	if !deadline.IsZero() {
		testHookStepTime()
		if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
			subCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			ctx = subCtx
		}
	}

	// check context done
	select {
	case <-ctx.Done():
		return nil, &net.OpError{Op: "dial", Net: network, Source: d.LocalAddr.opAddr(), Addr: raddr.opAddr(), Err: ctx.Err()}
	default:
	}

	if h := testHookDialSCTP; h != nil {
		return h(ctx, network, raddr, d)
	}

	return dialSCTP(ctx, network, raddr, d)
}

func dialSCTP(ctx context.Context, network string, raddr *SCTPAddr, d *Dialer) (*SCTPConn, error) {
	fd, err := clientSocket(ctx, network, raddr, d)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Source: d.LocalAddr.opAddr(), Addr: raddr.opAddr(), Err: err}
	}

	return newSCTPConn(fd), nil
}
