// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the GO_LICENSE file.

// This file contains test code from go's net package, tweaked for SCTP where necessary.

package sctp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func newLocalListenerSCTP(t testing.TB, network string, lcOpt ...*ListenConfig) net.Listener {
	var lc *ListenConfig
	switch len(lcOpt) {
	case 0:
		lc = new(ListenConfig)
	case 1:
		lc = lcOpt[0]
	default:
		t.Helper()
		t.Fatal("too many ListenConfigs passed to newLocalListener: want 0 or 1")
	}

	listen := func(net, addr string) net.Listener {
		ln, err := lc.Listen(net, addr)
		if err != nil {
			t.Helper()
			t.Fatal(err)
		}
		return ln
	}

	switch network {
	case "sctp":
		if supportsIPv4() {
			if !supportsIPv6() {
				return listen("sctp4", "127.0.0.1/127.0.0.2:0")
			}
			if ln, err := Listen("sctp4", "127.0.0.1/127.0.0.2:0"); err == nil {
				return ln
			}
		}
		if supportsIPv6() {
			return listen("sctp6", "[::1]:0")
		}
	case "sctp4":
		if supportsIPv4() {
			return listen("sctp4", "127.0.0.1/127.0.0.2:0")
		}
	case "sctp6":
		if supportsIPv6() {
			return listen("sctp6", "[::1]:0")
		}
	}

	t.Helper()
	t.Fatalf("%s is not supported", network)
	return nil
}

type localServerSCTP struct {
	lnmu sync.RWMutex
	net.Listener
	done chan bool  // signal that indicates server stopped
	cl   []net.Conn // accepted connection list
}

func (ls *localServerSCTP) buildup(handler func(*localServerSCTP, net.Listener)) error {
	go func() {
		handler(ls, ls.Listener)
		close(ls.done)
	}()
	return nil
}

func (ls *localServerSCTP) teardown() error {
	ls.lnmu.Lock()
	defer ls.lnmu.Unlock()
	if ls.Listener != nil {
		ls.Listener.Close()
		for _, c := range ls.cl {
			if err := c.Close(); err != nil {
				return err
			}
		}
		<-ls.done
		ls.Listener = nil
	}
	return nil
}

func (ls *localServerSCTP) transponder(ln net.Listener, ch chan<- error) {
	defer close(ch)
	switch ln := ln.(type) {
	case *SCTPListener:
		ln.SetDeadline(time.Now().Add(someTimeout))
	}
	c, err := ln.Accept()
	if err != nil {
		if perr := parseAcceptError(err); perr != nil {
			ch <- perr
		}
		ch <- err
		return
	}
	log.Printf("transponder accepted connection: %v <-------> %v ", c.LocalAddr(), c.RemoteAddr())
	ls.cl = append(ls.cl, c)

	network := ln.Addr().Network()
	if c.LocalAddr().Network() != network || c.RemoteAddr().Network() != network {
		ch <- fmt.Errorf("got %v->%v; expected %v->%v", c.LocalAddr().Network(), c.RemoteAddr().Network(), network, network)
		return
	}
	c.SetDeadline(time.Now().Add(someTimeout))
	c.SetReadDeadline(time.Now().Add(someTimeout))
	c.SetWriteDeadline(time.Now().Add(someTimeout))

	b := make([]byte, 256)
	n, err := c.Read(b)
	if err != nil {
		if perr := parseReadError(err); perr != nil {
			ch <- perr
		}
		ch <- err
		return
	}

	_, err = c.Write(b[:n])
	if err != nil {
		if perr := parseWriteError(err); perr != nil {
			ch <- perr
		}
		ch <- err
		return
	}
}

func transceiver(c net.Conn, wb []byte, ch chan<- error) {
	defer close(ch)

	c.SetDeadline(time.Now().Add(someTimeout))
	c.SetReadDeadline(time.Now().Add(someTimeout))
	c.SetWriteDeadline(time.Now().Add(someTimeout))

	n, err := c.Write(wb)
	if err != nil {
		if perr := parseWriteError(err); perr != nil {
			ch <- perr
		}
		ch <- err
		return
	}
	if n != len(wb) {
		ch <- fmt.Errorf("wrote %d; want %d", n, len(wb))
	}
	rb := make([]byte, len(wb))
	n, err = c.Read(rb)
	if err != nil {
		if perr := parseReadError(err); perr != nil {
			ch <- perr
		}
		ch <- err
		return
	}
	if n != len(wb) {
		ch <- fmt.Errorf("read %d; want %d", n, len(wb))
	}
}

func newLocalServerSCTP(t testing.TB, network string) *localServerSCTP {
	t.Helper()
	ln := newLocalListenerSCTP(t, network)
	return &localServerSCTP{Listener: ln, done: make(chan bool)}
}

func (ln *SCTPListener) port() string {
	i := strings.LastIndexByte(ln.Addr().String(), ':')
	if i < 0 {
		return ""
	}
	return ln.Addr().String()[i+1:]
}

func newDualStackListener() ([]*SCTPListener, error) {
	var args = []struct {
		network string
		SCTPAddr
	}{
		{"sctp4", SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}}},
		{"sctp6", SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv6loopback}}}},
	}
	for i := 0; i < 64; i++ {
		var port int
		var lns []*SCTPListener
		for _, arg := range args {
			arg.SCTPAddr.Port = port
			ln, err := ListenSCTP(arg.network, &arg.SCTPAddr)
			if err != nil {
				continue
			}
			port = ln.Addr().(*SCTPAddr).Port
			lns = append(lns, ln)
		}
		if len(lns) != len(args) {
			for _, ln := range lns {
				_ = ln.Close()
			}
			continue
		}
		return lns, nil
	}
	return nil, errors.New("no dualstack available")
}

type streamListener struct {
	network, address string
	net.Listener
	done chan bool // signal that indicates server stopped
}

func (sl *streamListener) newLocalServerSCTP() *localServerSCTP {
	return &localServerSCTP{Listener: sl.Listener, done: make(chan bool)}
}

type dualStackServer struct {
	lnmu sync.RWMutex
	lns  []streamListener
	port string

	cmu sync.RWMutex
	cs  []net.Conn // established connections at the passive open side
}

func (dss *dualStackServer) buildup(handler func(*dualStackServer, net.Listener)) error {
	for i := range dss.lns {
		go func(i int) {
			handler(dss, dss.lns[i].Listener)
			close(dss.lns[i].done)
		}(i)
	}
	return nil
}

func (dss *dualStackServer) teardownNetwork(network string) error {
	dss.lnmu.Lock()
	for i := range dss.lns {
		if network == dss.lns[i].network && dss.lns[i].Listener != nil {
			dss.lns[i].Listener.Close()
			<-dss.lns[i].done
			dss.lns[i].Listener = nil
		}
	}
	dss.lnmu.Unlock()
	return nil
}

func (dss *dualStackServer) teardown() error {
	dss.lnmu.Lock()
	for i := range dss.lns {
		if dss.lns[i].Listener != nil {
			dss.lns[i].Listener.Close()
			<-dss.lns[i].done
		}
	}
	dss.lns = dss.lns[:0]
	dss.lnmu.Unlock()
	dss.cmu.Lock()
	for _, c := range dss.cs {
		c.Close()
	}
	dss.cs = dss.cs[:0]
	dss.cmu.Unlock()
	return nil
}

func newDualStackServer() (*dualStackServer, error) {
	lns, err := newDualStackListener()
	if err != nil {
		return nil, err
	}
	port := lns[0].port()
	return &dualStackServer{
		lns: []streamListener{
			{network: "sctp4", address: lns[0].Addr().String(), Listener: lns[0], done: make(chan bool)},
			{network: "sctp6", address: lns[1].Addr().String(), Listener: lns[1], done: make(chan bool)},
		},
		port: port,
	}, nil
}

func controlOnConnSetup(network string, address string, c syscall.RawConn) error {
	var operr error
	var fn func(uintptr)
	switch network {
	case "sctp":
		return errors.New("ambiguous network: " + network)
	default:
		switch network[len(network)-1] {
		case '4':
			fn = func(s uintptr) {
				operr = syscall.SetsockoptInt(int(s), syscall.IPPROTO_IP, syscall.IP_TTL, 1)
			}
		case '6':
			fn = func(s uintptr) {
				operr = syscall.SetsockoptInt(int(s), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, 1)
			}
		default:
			return errors.New("unknown network: " + network)
		}
	}
	if err := c.Control(fn); err != nil {
		return err
	}
	return operr
}

// someTimeout is used just to test that net.Conn implementations
// don't explode when their SetFooDeadline methods are called.
// It isn't actually used for testing timeouts.
const someTimeout = 1 * time.Hour

// testableListenArgs reports whether arguments are testable on the
// current platform configuration.
func testableListenArgs(network, address, client string) bool {
	if !testableNetwork(network) {
		return false
	}

	var err error
	var addr net.Addr
	switch net, _, _ := strings.Cut(network, ":"); net {
	case "sctp", "sctp4", "sctp6":
		addr, err = resolveSCTPAddr("", "sctp", address, nil)
	default:
		return true
	}
	if err != nil {
		return false
	}
	var ip net.IP
	var wildcard bool
	switch addr := addr.(type) {
	case *SCTPAddr:
		ip = addr.IPAddrs[0].IP
		wildcard = addr.isWildcard()
	}

	// Test wildcard IP addresses.
	if wildcard {
		return false
	}

	// Test functionality of IPv4 communication using AF_INET and
	// IPv6 communication using AF_INET6 sockets.
	if !supportsIPv4() && ip.To4() != nil {
		return false
	}
	if !supportsIPv6() && ip.To16() != nil && ip.To4() == nil {
		return false
	}
	cip := net.ParseIP(client)
	if cip != nil {
		if !supportsIPv4() && cip.To4() != nil {
			return false
		}
		if !supportsIPv6() && cip.To16() != nil && cip.To4() == nil {
			return false
		}
	}

	// Test functionality of IPv4 communication using AF_INET6
	// sockets.
	if !supportsIPv4map() && supportsIPv4() && (network == "sctp") && wildcard {
		// At this point, we prefer IPv4 when ip is nil.
		// See favoriteAddrFamily for further information.
		if ip.To16() != nil && ip.To4() == nil && cip.To4() != nil { // a pair of IPv6 server and IPv4 client
			return false
		}
		if (ip.To4() != nil || ip == nil) && cip.To16() != nil && cip.To4() == nil { // a pair of IPv4 server and IPv6 client
			return false
		}
	}

	return true
}

// testableNetwork reports whether network is testable on the current
// platform configuration.
func testableNetwork(network string) bool {
	net, _, _ := strings.Cut(network, ":")
	switch net {
	case "sctp4":
		if !supportsIPv4() {
			return false
		}
	case "sctp6":
		if !supportsIPv6() {
			return false
		}
	}
	return true
}

// parseDialError parses nestedErr and reports whether it is a valid
// error value from Dial, Listen functions.
// It returns nil when nestedErr is valid.
func parseDialError(nestedErr error) error {
	if nestedErr == nil {
		return nil
	}

	switch err := nestedErr.(type) {
	case *net.OpError:
		if err := isValid(err); err != nil {
			return err
		}
		nestedErr = err.Err
		goto second
	}
	return fmt.Errorf("unexpected type on 1st nested level: %T", nestedErr)

second:
	if isPlatformError(nestedErr) {
		return nil
	}
	switch err := nestedErr.(type) {
	case *net.AddrError, *timeoutError, *net.DNSError, net.InvalidAddrError, *net.ParseError, net.UnknownNetworkError:
		return nil
	case interface{ isAddrinfoErrno() }:
		return nil
	case *os.SyscallError:
		nestedErr = err.Err
		goto third
	case *fs.PathError: // for Plan 9
		nestedErr = err.Err
		goto third
	}
	switch nestedErr {
	case errCanceled, net.ErrClosed, errMissingAddress, errNoSuitableAddress,
		context.DeadlineExceeded, context.Canceled:
		return nil
	}
	return fmt.Errorf("unexpected type on 2nd nested level: %T", nestedErr)

third:
	if isPlatformError(nestedErr) {
		return nil
	}
	return fmt.Errorf("unexpected type on 3rd nested level: %T", nestedErr)
}

// parseReadError parses nestedErr and reports whether it is a valid
// error value from Read functions.
// It returns nil when nestedErr is valid.
func parseReadError(nestedErr error) error {
	if nestedErr == nil {
		return nil
	}

	switch err := nestedErr.(type) {
	case *net.OpError:
		if err := isValid(err); err != nil {
			return err
		}
		nestedErr = err.Err
		goto second
	}
	if nestedErr == io.EOF {
		return nil
	}
	return fmt.Errorf("unexpected type on 1st nested level: %T", nestedErr)

second:
	if isPlatformError(nestedErr) {
		return nil
	}
	switch err := nestedErr.(type) {
	case *os.SyscallError:
		nestedErr = err.Err
		goto third
	case *fs.PathError:
		switch err.Err {
		case os.ErrClosed, errTimeout, os.ErrDeadlineExceeded:
			return nil
		}
		nestedErr = err.Err
		goto third
	}

	switch nestedErr {
	case net.ErrClosed, errTimeout, os.ErrDeadlineExceeded:
		return nil
	}
	return fmt.Errorf("unexpected type on 2nd nested level: %T", nestedErr)

third:
	if isPlatformError(nestedErr) {
		return nil
	}
	return fmt.Errorf("unexpected type on 3rd nested level: %T", nestedErr)
}

// parseWriteError parses nestedErr and reports whether it is a valid
// error value from Write functions.
// It returns nil when nestedErr is valid.
func parseWriteError(nestedErr error) error {
	if nestedErr == nil {
		return nil
	}

	switch err := nestedErr.(type) {
	case *net.OpError:
		if err := isValid(err); err != nil {
			return err
		}
		nestedErr = err.Err
		goto second
	}
	return fmt.Errorf("unexpected type on 1st nested level: %T", nestedErr)

second:
	if isPlatformError(nestedErr) {
		return nil
	}
	switch err := nestedErr.(type) {
	case *net.AddrError, *timeoutError, *net.DNSError, net.InvalidAddrError, *net.ParseError, net.UnknownNetworkError:
		return nil
	case interface{ isAddrinfoErrno() }:
		return nil
	case *os.SyscallError:
		nestedErr = err.Err
		goto third
	case *fs.PathError:
		switch err.Err {
		case os.ErrClosed, errTimeout, os.ErrDeadlineExceeded:
			return nil
		}
		nestedErr = err.Err
		goto third
	}
	switch nestedErr {
	case errCanceled, net.ErrClosed, errMissingAddress, errTimeout, os.ErrDeadlineExceeded, ErrWriteToConnected, io.ErrUnexpectedEOF:
		return nil
	}
	return fmt.Errorf("unexpected type on 2nd nested level: %T", nestedErr)

third:
	if isPlatformError(nestedErr) {
		return nil
	}
	return fmt.Errorf("unexpected type on 3rd nested level: %T", nestedErr)
}

// parseCloseError parses nestedErr and reports whether it is a valid
// error value from Close functions.
// It returns nil when nestedErr is valid.
func parseCloseError(nestedErr error, isShutdown bool) error {
	if nestedErr == nil {
		return nil
	}

	// Because historically we have not exported the error that we
	// return for an operation on a closed network connection,
	// there are programs that test for the exact error string.
	// Verify that string here so that we don't break those
	// programs unexpectedly. See issues #4373 and #19252.
	want := "use of closed network connection"
	if !isShutdown && !strings.Contains(nestedErr.Error(), want) {
		return fmt.Errorf("error string %q does not contain expected string %q", nestedErr, want)
	}

	if !isShutdown && !errors.Is(nestedErr, net.ErrClosed) {
		return fmt.Errorf("errors.Is(%v, errClosed) returns false, want true", nestedErr)
	}

	switch err := nestedErr.(type) {
	case *net.OpError:
		if err := isValid(err); err != nil {
			return err
		}
		nestedErr = err.Err
		goto second
	}
	return fmt.Errorf("unexpected type on 1st nested level: %T", nestedErr)

second:
	if isPlatformError(nestedErr) {
		return nil
	}
	switch err := nestedErr.(type) {
	case *os.SyscallError:
		nestedErr = err.Err
		goto third
	case *fs.PathError: // for Plan 9
		nestedErr = err.Err
		goto third
	}
	switch nestedErr {
	case net.ErrClosed:
		return nil
	}
	return fmt.Errorf("unexpected type on 2nd nested level: %T", nestedErr)

third:
	if isPlatformError(nestedErr) {
		return nil
	}
	switch nestedErr {
	case fs.ErrClosed: // for Plan 9
		return nil
	}
	return fmt.Errorf("unexpected type on 3rd nested level: %T", nestedErr)
}

// parseAcceptError parses nestedErr and reports whether it is a valid
// error value from Accept functions.
// It returns nil when nestedErr is valid.
func parseAcceptError(nestedErr error) error {
	if nestedErr == nil {
		return nil
	}

	switch err := nestedErr.(type) {
	case *net.OpError:
		if err := isValid(err); err != nil {
			return err
		}
		nestedErr = err.Err
		goto second
	}
	return fmt.Errorf("unexpected type on 1st nested level: %T", nestedErr)

second:
	if isPlatformError(nestedErr) {
		return nil
	}
	switch err := nestedErr.(type) {
	case *os.SyscallError:
		nestedErr = err.Err
		goto third
	case *fs.PathError: // for Plan 9
		nestedErr = err.Err
		goto third
	}
	switch nestedErr {
	case net.ErrClosed, errTimeout, os.ErrDeadlineExceeded:
		return nil
	}
	return fmt.Errorf("unexpected type on 2nd nested level: %T", nestedErr)

third:
	if isPlatformError(nestedErr) {
		return nil
	}
	return fmt.Errorf("unexpected type on 3rd nested level: %T", nestedErr)
}

// parseCommonError parses nestedErr and reports whether it is a valid
// error value from miscellaneous functions.
// It returns nil when nestedErr is valid.
func parseCommonError(nestedErr error) error {
	if nestedErr == nil {
		return nil
	}

	switch err := nestedErr.(type) {
	case *net.OpError:
		if err := isValid(err); err != nil {
			return err
		}
		nestedErr = err.Err
		goto second
	}
	return fmt.Errorf("unexpected type on 1st nested level: %T", nestedErr)

second:
	if isPlatformError(nestedErr) {
		return nil
	}
	switch err := nestedErr.(type) {
	case *os.SyscallError:
		nestedErr = err.Err
		goto third
	case *os.LinkError:
		nestedErr = err.Err
		goto third
	case *fs.PathError:
		nestedErr = err.Err
		goto third
	}
	switch nestedErr {
	case net.ErrClosed:
		return nil
	}
	return fmt.Errorf("unexpected type on 2nd nested level: %T", nestedErr)

third:
	if isPlatformError(nestedErr) {
		return nil
	}
	return fmt.Errorf("unexpected type on 3rd nested level: %T", nestedErr)
}

func isValid(e *net.OpError) error {
	if e.Op == "" {
		return fmt.Errorf("OpError.Op is empty: %v", e)
	}
	if e.Net == "" {
		return fmt.Errorf("OpError.Net is empty: %v", e)
	}
	for _, addr := range []net.Addr{e.Source, e.Addr} {
		switch addr := addr.(type) {
		case nil:
		case *SCTPAddr:
			if addr == nil {
				return fmt.Errorf("OpError.Source or Addr is non-nil interface: %#v, %v", addr, e)
			}
		case *net.TCPAddr:
			if addr == nil {
				return fmt.Errorf("OpError.Source or Addr is non-nil interface: %#v, %v", addr, e)
			}
		default:
			return fmt.Errorf("OpError.Source or Addr is unknown type: %T, %v", addr, e)
		}
	}
	if e.Err == nil {
		return fmt.Errorf("OpError.Err is empty: %v", e)
	}
	return nil
}

func isPlatformError(err error) bool {
	_, ok := err.(syscall.Errno)
	return ok
}

func samePlatformError(err, want error) bool {
	if op, ok := err.(*net.OpError); ok {
		err = op.Err
	}
	if sys, ok := err.(*os.SyscallError); ok {
		err = sys.Err
	}
	return err == want
}
