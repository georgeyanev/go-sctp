package sctp

import (
	"context"
	"net"
	"os"
	"syscall"
)

type SCTPListener struct {
	c  *conn
	lc *ListenConfig
}

// ListenConfig TODO: possibly add more fields (specific to SCTP)
// ListenConfig contains options for listening to an address.
type ListenConfig struct {
	// If Control is not nil, it is called after creating the network
	// connection but before binding it to the operating system.
	//
	// Network and address parameters passed to Control method are not
	// necessarily the ones passed to Listen. For example, passing "sctp" to
	// Listen will cause the Control function to be called with "sctp4" or "sctp6".
	Control func(network, address string, c syscall.RawConn) error

	// provides information for initializing new SCTP associations
	InitMsg InitMsg

	// heartbeats are enabled by default and the interval between them are defined in `net.sctp.hb_interval`
	// kernel parameter which is 30 seconds by default
	// TO DO: make an option to disable them? Disabling means disable only sending heartbeats

}

// Listen announces on the local network address.
//
// The network must be "sctp", "sctp4" or "sctp6".
//
// If the host in the address parameter is empty or
// a literal unspecified IP address, Listen listens on all available
// IP addresses of the local system.
// To only use IPv4, use network "sctp4".
// The address can use a host name, but this is not recommended,
// because it will create a listener for at most one of the host's IP
// addresses.
// If the port in the address parameter is empty or "0", as in
// "127.0.0.1:" or "[::1]:0", a port number is automatically chosen.
// The [Addr] method of [Listener] can be used to discover the chosen
// port.
// Multiple addresses can be specified separated by '/' as in :
// 127.0.0.1/127.0.0.2:0 (sctp4 network)
// [::1]/[::2]:0 (sctp6 network)
// [::1]/127.0.0.1:0 (sctp network)
// For an extensive list of possibilities consult listen_test.go
//
// Listen uses context.Background internally; to specify the context, use
// [ListenConfig.Listen].
func Listen(network, address string) (net.Listener, error) {
	var lc ListenConfig
	return lc.Listen(context.Background(), network, address)
}

// ListenSCTP acts like [Listen] for SCTP networks.
//
// # The network must be a SCTP network name
//
// If the IP field of laddr is nil or an unspecified IP address,
// ListenSCTP listens on all available IP addresses of the local system.
// If the Port field of laddr is 0, a port number is automatically
// chosen.
func ListenSCTP(network string, laddr *SCTPAddr) (*SCTPListener, error) {
	var lc ListenConfig
	return lc.ListenSCTP(context.Background(), network, laddr)
}

func (lc *ListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	// resolve the address
	laddr, err := resolveSCTPAddr("listen", network, address)
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
	}
	return lc.ListenSCTP(ctx, network, laddr)
}

func (lc *ListenConfig) ListenSCTP(ctx context.Context, network string, laddr *SCTPAddr) (*SCTPListener, error) {
	// check network
	switch network {
	case "sctp", "sctp4", "sctp6":
	default:
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: net.UnknownNetworkError(network)}
	}
	return listenSCTP(ctx, network, laddr, lc)
}

func listenSCTP(ctx context.Context, network string, laddr *SCTPAddr, lc *ListenConfig) (*SCTPListener, error) {
	var ctrlCtxFn func(cxt context.Context, network, address string, c syscall.RawConn) error
	if lc.Control != nil {
		ctrlCtxFn = func(cxt context.Context, network, address string, c syscall.RawConn) error {
			return lc.Control(network, address, c)
		}
	}

	if lc.InitMsg.NumOstreams == 0 { // set default value
		lc.InitMsg.NumOstreams = 10
	}
	if lc.InitMsg.MaxInstreams == 0 { // set default value
		lc.InitMsg.MaxInstreams = 10
	}

	c, err := serverSocket(ctx, network, laddr, &lc.InitMsg, ctrlCtxFn)
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: err}
	}
	return &SCTPListener{c: c, lc: lc}, nil
}

func (ln *SCTPListener) Accept() (net.Conn, error) {
	// TODO:
	return nil, nil
}

func (ln *SCTPListener) Addr() net.Addr {
	if !ln.ok() {
		return nil
	}
	return ln.c.LocalAddr()
}

func (ln *SCTPListener) Close() error {
	if !ln.ok() {
		return os.ErrInvalid
	}
	if err := ln.close(); err != nil {
		return &net.OpError{Op: "close", Net: ln.c.net, Source: nil, Addr: ln.c.laddr.Load(), Err: err}
	}
	return nil
}

func (ln *SCTPListener) Binder() Binder {
	if !ln.ok() {
		return nil
	}
	return ln.c
}

func (ln *SCTPListener) ok() bool { return ln != nil && ln.c != nil }

func (ln *SCTPListener) close() error {
	return ln.c.Close()
}
