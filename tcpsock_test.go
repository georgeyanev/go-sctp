// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sctp

import (
	"fmt"
	"io"
	"net"
	"testing"
)

// Test that >32-bit reads work on 64-bit systems.
// On 32-bit systems this tests that maxint reads work.
func TestTCPBig(t *testing.T) {
	t.Skip("Skip")
	for _, writev := range []bool{false, true} {
		t.Run(fmt.Sprintf("writev=%v", writev), func(t *testing.T) {
			ln := newLocalListener(t, "tcp")
			defer ln.Close()

			x := int(1 << 30)
			x = x*5 + 1<<20 // just over 5 GB on 64-bit, just over 1GB on 32-bit
			done := make(chan int)
			go func() {
				defer close(done)
				c, err := ln.Accept()
				if err != nil {
					t.Error(err)
					return
				}
				buf := make([]byte, x)
				var n int
				if writev {
					var n64 int64
					n64, err = (&net.Buffers{buf}).WriteTo(c)
					n = int(n64)
				} else {
					n, err = c.Write(buf)
				}
				if n != len(buf) || err != nil {
					t.Errorf("Write(buf) = %d, %v, want %d, nil", n, err, x)
				}
				c.Close()
			}()

			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, x)
			n, err := io.ReadFull(c, buf)
			if n != len(buf) || err != nil {
				t.Errorf("Read(buf) = %d, %v, want %d, nil", n, err, x)
			}
			c.Close()
			<-done
		})
	}
}

func writeAllTCP(c net.Conn, p []byte) (int, error) {
	//wBufSize, err := c.fd.getSendBuffer()
	wBufSize := 8192
	var nn int
	for {
		maxL := len(p)
		if maxL-nn > wBufSize {
			maxL = nn + wBufSize
		}

		n, err := c.Write(p[nn:maxL])
		if n > 0 {
			nn += n
		}
		if nn == len(p) {
			return nn, err
		}
		if err != nil {
			return nn, err
		}
		//log.Printf("%d bytes written", nn)
	}
}
