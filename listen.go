package sctp

import (
	"errors"
	"log"
	"net"
	"syscall"
	"time"
)

type SCTPListener struct {
	fd *sctpFD
	lc *ListenConfig
}

// ListenConfig contains options for listening to an address.
// ListenConfig TO DO: possibly add more fields (specific to SCTP)
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

	// SCTP heartbeats are enabled by default and the interval between them are defined
	// in `net.sctp.hb_interval` kernel parameter which is 30 seconds by default.
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
	return lc.Listen(network, address)
}

// ListenSCTP acts like [Listen] for SCTP networks.
//
// If the IP field of laddr is nil or an unspecified IP address,
// ListenSCTP listens on all available IP addresses of the local system.
// If the Port field of laddr is 0, a port number is automatically
// chosen.
func ListenSCTP(network string, laddr *SCTPAddr) (*SCTPListener, error) {
	var lc ListenConfig
	return lc.ListenSCTP(network, laddr)
}

func (lc *ListenConfig) Listen(network, address string) (net.Listener, error) {
	// resolve the address
	laddr, err := resolveSCTPAddr("listen", network, address, nil)
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
	}
	return lc.ListenSCTP(network, laddr)
}

func (lc *ListenConfig) ListenSCTP(network string, laddr *SCTPAddr) (*SCTPListener, error) {
	// check network
	switch network {
	case "sctp", "sctp4", "sctp6":
	default:
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: net.UnknownNetworkError(network)}
	}
	return listenSCTP(network, laddr, lc)
}

func listenSCTP(network string, laddr *SCTPAddr, lc *ListenConfig) (*SCTPListener, error) {
	if lc.InitMsg.NumOstreams == 0 { // set default value
		lc.InitMsg.NumOstreams = 10
	}
	if lc.InitMsg.MaxInstreams == 0 { // set default value
		lc.InitMsg.MaxInstreams = 10
	}

	fd, err := serverSocket(network, laddr, lc)
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: err}
	}
	return &SCTPListener{fd: fd, lc: lc}, nil
}

// Accept implements the Accept method in the [Listener] interface; it
// waits for the next call and returns a generic [Conn].
func (ln *SCTPListener) Accept() (net.Conn, error) {
	return ln.AcceptSCTP()
}

// AcceptSCTP accepts the next incoming call and returns the new connection.
func (ln *SCTPListener) AcceptSCTP() (*SCTPConn, error) {
	log.Printf("gId %d: func ln.AcceptSCTP", getGoroutineID()) // TODO: remove()
	if !ln.ok() {
		return nil, syscall.EINVAL
	}
	c, err := ln.accept()
	if err != nil {
		return nil, &net.OpError{Op: "accept", Net: ln.fd.net, Source: nil, Addr: ln.fd.laddr.Load().opAddr(), Err: err}
	}
	return c, nil
}

func (ln *SCTPListener) Addr() net.Addr {
	if !ln.ok() {
		return nil
	}
	return ln.fd.laddr.Load()
}

func (ln *SCTPListener) Close() error {
	if !ln.ok() {
		return errEINVAL
	}
	if err := ln.close(); err != nil {
		return &net.OpError{Op: "close", Net: ln.fd.net, Source: nil, Addr: ln.fd.laddr.Load().opAddr(), Err: err}
	}
	return nil
}

// SetDeadline sets the deadline associated with the listener.
// A zero time value disables the deadline.
func (ln *SCTPListener) SetDeadline(t time.Time) error {
	if !ln.ok() {
		return errEINVAL
	}
	return ln.fd.f.SetDeadline(t)
}

// BindAdd associates additional addresses with an already bound endpoint (i.e. socket).
// If the endpoint supports dynamic address reconfiguration, BindAdd may cause an
// endpoint to send the appropriate message to its peers to change the peers' address lists.
// New accepted associations will be associated with these
// addresses in addition to the already present ones
// Port number should be equal to the already bound port.
func (ln *SCTPListener) BindAdd(address string) error {
	if !ln.ok() {
		return errEINVAL
	}
	laddr, err := resolveSCTPAddr("bindx", ln.fd.net, address, nil)
	if err != nil {
		return &net.OpError{Op: "bindx", Net: ln.fd.net, Source: nil, Addr: ln.fd.laddr.Load(),
			Err: errors.New("add address: " + address + ": " + err.Error())}
	}
	if err = ln.BindAddSCTP(laddr); err != nil {
		return err
	}
	return nil
}

func (ln *SCTPListener) BindAddSCTP(laddr *SCTPAddr) error {
	if !ln.ok() {
		return errEINVAL
	}
	if err := ln.fd.bind(laddr, _SCTP_SOCKOPT_BINDX_ADD); err != nil {
		return &net.OpError{Op: "bindx", Net: ln.fd.net, Source: nil, Addr: ln.fd.laddr.Load(),
			Err: errors.New("add address: " + laddr.String() + ": " + err.Error())}
	}
	return nil
}

// BindRemove remove some addresses with which a bound socket is associated.
// New associations accepted will not be associated with these addresses
// Port number should be equal to the already bound port.
func (ln *SCTPListener) BindRemove(address string) error {
	if !ln.ok() {
		return errEINVAL
	}
	laddr, err := resolveSCTPAddr("bindx", ln.fd.net, address, nil)
	if err != nil {
		return &net.OpError{Op: "bindx", Net: ln.fd.net, Source: nil, Addr: ln.fd.laddr.Load(),
			Err: errors.New("remove address: " + address + ": " + err.Error())}
	}
	if err = ln.BindRemoveSCTP(laddr); err != nil {
		return err
	}
	return nil

}

func (ln *SCTPListener) BindRemoveSCTP(laddr *SCTPAddr) error {
	if !ln.ok() {
		return errEINVAL
	}
	if err := ln.fd.bind(laddr, _SCTP_SOCKOPT_BINDX_REM); err != nil {
		return &net.OpError{Op: "bindx", Net: ln.fd.net, Source: nil, Addr: ln.fd.laddr.Load(),
			Err: errors.New("remove address: " + laddr.String() + ": " + err.Error())}
	}
	return nil
}

func (ln *SCTPListener) ok() bool { return ln != nil && ln.fd != nil }

func (ln *SCTPListener) close() error {
	if !ln.ok() {
		return errEINVAL
	}
	return ln.fd.f.Close()
}

func (ln *SCTPListener) accept() (*SCTPConn, error) {
	if !ln.ok() {
		return nil, errEINVAL
	}
	log.Printf("gId %d: func ln.accept", getGoroutineID())
	fd, err := ln.fd.accept()
	if err != nil {
		return nil, err
	}
	return newSCTPConnNew(fd), nil
}
