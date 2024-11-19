package sctp

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"
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

func (ls *localServer) transponder(ln net.Listener, ch chan<- error) {
	defer close(ch)

	switch ln := ln.(type) {
	case *net.TCPListener:
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
	if _, err := c.Write(b[:n]); err != nil {
		if perr := parseWriteError(err); perr != nil {
			ch <- perr
		}
		ch <- err
		return
	}
}
