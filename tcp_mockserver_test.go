package sctp

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
)

func newLocalListener(t testing.TB, network string, lcOpt ...*net.ListenConfig) net.Listener {
	var lc *net.ListenConfig
	switch len(lcOpt) {
	case 0:
		lc = new(net.ListenConfig)
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
	case "tcp":
		if supportsIPv4() {
			if !supportsIPv6() {
				return listen("tcp4", "127.0.0.1:0")
			}
			if ln, err := Listen("tcp", "127.0.0.1:0"); err == nil {
				return ln
			}
		}
		if supportsIPv6() {
			return listen("tcp6", "[::1]:0")
		}
	case "tcp4":
		if supportsIPv4() {
			return listen("tcp4", "127.0.0.1:0")
		}
	case "tcp6":
		if supportsIPv6() {
			return listen("tcp6", "[::1]:0")
		}
	}

	t.Helper()
	t.Fatalf("%s is not supported", network)
	return nil
}

type localServer struct {
	lnmu sync.RWMutex
	net.Listener
	done chan bool  // signal that indicates server stopped
	cl   []net.Conn // accepted connection list
}

func (ls *localServer) buildup(handler func(*localServer, net.Listener)) error {
	go func() {
		handler(ls, ls.Listener)
		close(ls.done)
	}()
	return nil
}

func (ls *localServer) teardown() error {
	ls.lnmu.Lock()
	defer ls.lnmu.Unlock()
	if ls.Listener != nil {
		network := ls.Listener.Addr().Network()
		address := ls.Listener.Addr().String()
		ls.Listener.Close()
		for _, c := range ls.cl {
			if err := c.Close(); err != nil {
				return err
			}
		}
		<-ls.done
		ls.Listener = nil
		switch network {
		case "unix", "unixpacket":
			os.Remove(address)
		}
	}
	return nil
}

func newLocalServer(t testing.TB, network string) *localServer {
	t.Helper()
	ln := newLocalListener(t, network)
	return &localServer{Listener: ln, done: make(chan bool)}
}
