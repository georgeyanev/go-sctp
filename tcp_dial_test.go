package sctp

import (
	"bufio"
	"io"
	"net"
	"sync"
	"testing"
)

func TestDialerLocalAddr(t *testing.T) {
	if !supportsIPv4() || !supportsIPv6() {
		t.Skip("both IPv4 and IPv6 are required")
	}

	type test struct {
		network, raddr string
		laddr          net.Addr
		error
	}
	var tests = []test{
		{"tcp", "127.0.0.1", &net.TCPAddr{IP: net.IPv6loopback}, errNoSuitableAddress},
	}

	handler := func(ls *localServer, ln net.Listener) {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}
	var lss [2]*localServer
	for i, network := range []string{"tcp4", "tcp6"} {
		lss[i] = newLocalServer(t, network)
		defer lss[i].teardown()
		if err := lss[i].buildup(handler); err != nil {
			t.Fatal(err)
		}
	}

	for _, tt := range tests {
		d := &net.Dialer{LocalAddr: tt.laddr}
		var addr string
		ip := net.ParseIP(tt.raddr)
		if ip.To4() != nil {
			addr = lss[0].Listener.Addr().String()
		}
		if ip.To16() != nil && ip.To4() == nil {
			addr = lss[1].Listener.Addr().String()
		}
		c, err := d.Dial(tt.network, addr)
		if err == nil && tt.error != nil || err != nil && tt.error == nil {
			t.Errorf("%s %v->%s: got %v; want %v", tt.network, tt.laddr, tt.raddr, err, tt.error)
		}
		if err != nil {
			if perr := parseDialError(err); perr != nil {
				t.Error(perr)
			}
			continue
		}
		c.Close()
	}
}

func TestCancelAfterDial(t *testing.T) {
	if testing.Short() {
		t.Skip("avoiding time.Sleep")
	}

	ln := newLocalListener(t, "tcp")

	var wg sync.WaitGroup
	wg.Add(1)
	defer func() {
		ln.Close()
		wg.Wait()
	}()

	// Echo back the first line of each incoming connection.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				break
			}
			rb := bufio.NewReader(c)
			line, err := rb.ReadString('\n')
			if err != nil {
				t.Error(err)
				c.Close()
				continue
			}
			if _, err := c.Write([]byte(line)); err != nil {
				t.Error(err)
			}
			c.Close()
		}
		wg.Done()
	}()

	try := func() {
		//cancel := make(chan struct{})
		d := &net.Dialer{}
		c, err := d.Dial("tcp", ln.Addr().String())

		// Immediately after dialing, request cancellation and sleep.
		// Before Issue 15078 was fixed, this would cause subsequent operations
		// to fail with an i/o timeout roughly 50% of the time.
		//close(cancel)
		//time.Sleep(10 * time.Millisecond)

		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()

		// Send some data to confirm that the connection is still alive.
		const message = "echo!\n"
		if _, err := c.Write([]byte(message)); err != nil {
			t.Fatal(err)
		}

		// The server should echo the line, and close the connection.
		rb := bufio.NewReader(c)
		line, err := rb.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line != message {
			t.Errorf("got %q; want %q", line, message)
		}
		if _, err := rb.ReadByte(); err != io.EOF {
			t.Errorf("got %v; want %v", err, io.EOF)
		}
	}

	// This bug manifested about 50% of the time, so try it a few times.
	for i := 0; i < 100000; i++ {
		try()
	}
}
