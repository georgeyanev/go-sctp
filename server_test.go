// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the GO_LICENSE file.

// This file contains test code from go's net package, tweaked for SCTP where necessary.

package sctp

import (
	"log"
	"net"
	"testing"
)

var sctpServerTests = []struct {
	snet, saddr string // server endpoint
	tnet, taddr string // target endpoint for client
}{
	{snet: "sctp", saddr: ":0", tnet: "sctp", taddr: "127.0.0.1"},
	{snet: "sctp", saddr: "0.0.0.0:0", tnet: "sctp", taddr: "127.0.0.1"},
	{snet: "sctp", saddr: "[::ffff:0.0.0.0]:0", tnet: "sctp", taddr: "127.0.0.1"},
	{snet: "sctp", saddr: "[::]:0", tnet: "sctp", taddr: "[::1]"},

	{snet: "sctp", saddr: ":0", tnet: "sctp", taddr: "[::1]"},
	{snet: "sctp", saddr: "0.0.0.0:0", tnet: "sctp", taddr: "[::1]"},
	{snet: "sctp", saddr: "[::ffff:0.0.0.0]:0", tnet: "sctp", taddr: "[::1]"},
	{snet: "sctp", saddr: "[::]:0", tnet: "sctp", taddr: "127.0.0.1"},

	{snet: "sctp", saddr: ":0", tnet: "sctp4", taddr: "127.0.0.1"},
	{snet: "sctp", saddr: "0.0.0.0:0", tnet: "sctp4", taddr: "127.0.0.1"},
	{snet: "sctp", saddr: "[::ffff:0.0.0.0]:0", tnet: "sctp4", taddr: "127.0.0.1"},
	{snet: "sctp", saddr: "[::]:0", tnet: "sctp6", taddr: "[::1]"},

	{snet: "sctp", saddr: ":0", tnet: "sctp6", taddr: "[::1]"},
	{snet: "sctp", saddr: "0.0.0.0:0", tnet: "sctp6", taddr: "[::1]"},
	{snet: "sctp", saddr: "[::ffff:0.0.0.0]:0", tnet: "sctp6", taddr: "[::1]"},
	{snet: "sctp", saddr: "[::]:0", tnet: "sctp4", taddr: "127.0.0.1"},

	{snet: "sctp", saddr: "127.0.0.1:0", tnet: "sctp", taddr: "127.0.0.1"},
	{snet: "sctp", saddr: "[::ffff:127.0.0.1]:0", tnet: "sctp", taddr: "127.0.0.1"},
	{snet: "sctp", saddr: "[::1]:0", tnet: "sctp", taddr: "[::1]"},

	{snet: "sctp4", saddr: ":0", tnet: "sctp4", taddr: "127.0.0.1"},
	{snet: "sctp4", saddr: "0.0.0.0:0", tnet: "sctp4", taddr: "127.0.0.1"},
	{snet: "sctp4", saddr: "[::ffff:0.0.0.0]:0", tnet: "sctp4", taddr: "127.0.0.1"},

	{snet: "sctp4", saddr: "127.0.0.1:0", tnet: "sctp4", taddr: "127.0.0.1"},

	{snet: "sctp6", saddr: ":0", tnet: "sctp6", taddr: "[::1]"},
	{snet: "sctp6", saddr: "[::]:0", tnet: "sctp6", taddr: "[::1]"},

	{snet: "sctp6", saddr: "[::1]:0", tnet: "sctp6", taddr: "[::1]"},
}

// TestTCPServer tests concurrent accept-read-write servers.
func TestSCTPServer(t *testing.T) {
	const N = 3

	for i, tt := range sctpServerTests {
		t.Run(tt.snet+" "+tt.saddr+"<-"+tt.taddr, func(t *testing.T) {
			//if !testableListenArgs(tt.snet, tt.saddr, tt.taddr) {
			//	t.Skip("not testable")
			//}

			ln, err := Listen(tt.snet, tt.saddr)
			if err != nil {
				if perr := parseDialError(err); perr != nil {
					t.Error(perr)
				}
				t.Fatal(err)
			}
			log.Printf("gID: %d, listening on %v", getGoroutineID(), ln.Addr())

			var lss []*localServerSCTP
			var tpchs []chan error
			defer func() {
				for _, ls := range lss {
					ls.teardown()
				}
			}()
			for i := 0; i < N; i++ {
				ls := (&streamListener{Listener: ln}).newLocalServerSCTP()
				lss = append(lss, ls)
				tpchs = append(tpchs, make(chan error, 1))
			}
			for i := 0; i < N; i++ {
				ch := tpchs[i]
				handler := func(ls *localServerSCTP, ln net.Listener) { ls.transponder(ln, ch) }
				if err := lss[i].buildup(handler); err != nil {
					t.Fatal(err)
				}
			}

			var trchs []chan error
			for i := 0; i < N; i++ {
				port := lss[i].Listener.(*SCTPListener).port()
				if err != nil {
					t.Fatal(err)
				}
				d := Dialer{Timeout: someTimeout}
				log.Printf("gID: %d, about to dial %s", getGoroutineID(), tt.taddr+":"+port)
				c, err := d.Dial(tt.tnet, tt.taddr+":"+port)
				if err != nil {
					if perr := parseDialError(err); perr != nil {
						t.Error(perr)
					}
					t.Fatal(err)
				}
				log.Printf("gID: %d, dialed connection: %v <-------> %v ", getGoroutineID(), c.LocalAddr(), c.RemoteAddr())

				defer func(c net.Conn) {
					log.Printf("gID: %d, closing dialed connection... ", getGoroutineID())
					_ = c.Close()
				}(c)
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
