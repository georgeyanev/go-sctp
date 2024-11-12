// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the GO_LICENSE file.

// This file contains test code from go's net package, tweaked for SCTP where necessary.

package sctp

import (
	"context"
	"errors"
	"net"
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
		ln, err := lc.Listen(context.Background(), net, addr)
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

func (sl *streamListener) newLocalServer() *localServer {
	return &localServer{Listener: sl.Listener, done: make(chan bool)}
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
