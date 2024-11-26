package main

import (
	"github.com/georgeyanev/go-sctp"
	"log"
	"net"
	"time"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
}

// For a server, execute: `sctp_test -H 127.0.0.1 -P 33334 -T -l -d 0` from lksctp-tools package.
// For this to pass fast, a larger socket buffers are required (i.e. 4MB) and larger single message size (i.e. 256K).
func main() {
	c, err := sctp.Dial("sctp", "127.0.0.1:33334")
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	x := 1024 * 1024 * 1024 * 5 // 5G
	p := make([]byte, x)

	wBuf, err := c.(*sctp.SCTPConn).GetWriteBuffer()
	if err != nil {
		log.Fatal(err)
	}
	rBuf, err := c.(*sctp.SCTPConn).GetReadBuffer()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Read/Write buffer sizes: %d/%d", rBuf, wBuf)

	start := time.Now()
	_, err = writeAll(c, p)
	if err != nil {
		log.Fatal(err)
	}
	elapsed := time.Since(start)
	log.Printf("Time elapsed: %.3f seconds\n", elapsed.Seconds())
}

// Writes a big buffer (greater than a socket send buffer) to the conn object
// splitting the buffer into smaller peaces and writing them one by one.
// we cannot pass the large buffer to c.Write because it will not fit in the socket buffer
// and the function will return EMSGSIZE.
// See: https://datatracker.ietf.org/doc/html/rfc6458#page-67

func writeAll(c net.Conn, p []byte) (int, error) {
	wBufSize := 1024

	var nn, lastReported int
	for {
		maxL := len(p)
		if maxL-nn > wBufSize {
			maxL = nn + wBufSize
		}

		//n, err := c.Write(p[nn:maxL])
		//sndInfo := sctp.SndInfo{Sid: 1}
		n, err := c.(*sctp.SCTPConn).WriteMsg(p[nn:maxL], nil)
		if n > 0 {
			nn += n
		}
		if nn == len(p) {
			return nn, err
		}
		if err != nil {
			return nn, err
		}
		if (nn - lastReported) >= 1024*1024*100 { //10MB
			log.Printf("%d bytes written", nn)
			lastReported = nn
		}
	}
}
