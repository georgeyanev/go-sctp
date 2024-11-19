// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sctp

import (
	"net"
	"testing"
)

var tcpServerTests = []struct {
	snet, saddr string // server endpoint
	tnet, taddr string // target endpoint for client
}{
	//{snet: "tcp", saddr: ":0", tnet: "tcp", taddr: "127.0.0.1"},
	//{snet: "tcp", saddr: "0.0.0.0:0", tnet: "tcp", taddr: "127.0.0.1"},
	//{snet: "tcp", saddr: "[::ffff:0.0.0.0]:0", tnet: "tcp", taddr: "127.0.0.1"},
	//{snet: "tcp", saddr: "[::]:0", tnet: "tcp", taddr: "::1"},
	//
	//{snet: "tcp", saddr: ":0", tnet: "tcp", taddr: "::1"},
	//{snet: "tcp", saddr: "0.0.0.0:0", tnet: "tcp", taddr: "::1"},
	//{snet: "tcp", saddr: "[::ffff:0.0.0.0]:0", tnet: "tcp", taddr: "::1"},
	//{snet: "tcp", saddr: "[::]:0", tnet: "tcp", taddr: "127.0.0.1"},
	//
	//{snet: "tcp", saddr: ":0", tnet: "tcp4", taddr: "127.0.0.1"},
	//{snet: "tcp", saddr: "0.0.0.0:0", tnet: "tcp4", taddr: "127.0.0.1"},
	//{snet: "tcp", saddr: "[::ffff:0.0.0.0]:0", tnet: "tcp4", taddr: "127.0.0.1"},
	//{snet: "tcp", saddr: "[::]:0", tnet: "tcp6", taddr: "::1"},
	//
	//{snet: "tcp", saddr: ":0", tnet: "tcp6", taddr: "::1"},
	//{snet: "tcp", saddr: "0.0.0.0:0", tnet: "tcp6", taddr: "::1"},
	//{snet: "tcp", saddr: "[::ffff:0.0.0.0]:0", tnet: "tcp6", taddr: "::1"},
	{snet: "tcp", saddr: "[::]:0", tnet: "tcp4", taddr: "127.0.0.1"},
	//
	//{snet: "tcp", saddr: "127.0.0.1:0", tnet: "tcp", taddr: "127.0.0.1"},
	//{snet: "tcp", saddr: "[::ffff:127.0.0.1]:0", tnet: "tcp", taddr: "127.0.0.1"},
	//{snet: "tcp", saddr: "[::1]:0", tnet: "tcp", taddr: "::1"},
	//
	//{snet: "tcp4", saddr: ":0", tnet: "tcp4", taddr: "127.0.0.1"},
	//{snet: "tcp4", saddr: "0.0.0.0:0", tnet: "tcp4", taddr: "127.0.0.1"},
	//{snet: "tcp4", saddr: "[::ffff:0.0.0.0]:0", tnet: "tcp4", taddr: "127.0.0.1"},
	//
	//{snet: "tcp4", saddr: "127.0.0.1:0", tnet: "tcp4", taddr: "127.0.0.1"},
	//
	//{snet: "tcp6", saddr: ":0", tnet: "tcp6", taddr: "::1"},
	//{snet: "tcp6", saddr: "[::]:0", tnet: "tcp6", taddr: "::1"},
	//
	//{snet: "tcp6", saddr: "[::1]:0", tnet: "tcp6", taddr: "::1"},
}

// TestTCPServer tests concurrent accept-read-write servers.
func TestTCPServer(t *testing.T) {
	const N = 3

	for i, tt := range tcpServerTests {
		t.Run(tt.snet+" "+tt.saddr+"<-"+tt.taddr, func(t *testing.T) {
			if !testableListenArgs(tt.snet, tt.saddr, tt.taddr) {
				t.Skip("not testable")
			}

			ln, err := net.Listen(tt.snet, tt.saddr)
			if err != nil {
				if perr := parseDialError(err); perr != nil {
					t.Error(perr)
				}
				t.Fatal(err)
			}

			var lss []*localServer
			var tpchs []chan error
			defer func() {
				for _, ls := range lss {
					ls.teardown()
				}
			}()
			for i := 0; i < N; i++ {
				ls := (&streamListener{Listener: ln}).newLocalServer()
				lss = append(lss, ls)
				tpchs = append(tpchs, make(chan error, 1))
			}
			for i := 0; i < N; i++ {
				ch := tpchs[i]
				handler := func(ls *localServer, ln net.Listener) { ls.transponder(ln, ch) }
				if err := lss[i].buildup(handler); err != nil {
					t.Fatal(err)
				}
			}

			var trchs []chan error
			for i := 0; i < N; i++ {
				_, port, err := net.SplitHostPort(lss[i].Listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				d := net.Dialer{Timeout: someTimeout}
				c, err := d.Dial(tt.tnet, net.JoinHostPort(tt.taddr, port))
				if err != nil {
					if perr := parseDialError(err); perr != nil {
						t.Error(perr)
					}
					t.Fatal(err)
				}
				defer c.Close()
				trchs = append(trchs, make(chan error, 1))
				go transceiver(c, []byte("TCP SERVER TEST"), trchs[i])
			}

			for _, ch := range trchs {
				for err := range ch {
					t.Errorf("#%d: %v", i, err)
				}
			}
			for _, ch := range tpchs {
				for err := range ch {
					t.Errorf("#%d: %v", i, err)
				}
			}
		})
	}
}
