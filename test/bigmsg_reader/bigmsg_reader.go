package main

import (
	"github.com/georgeyanev/go-sctp"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	ln, err := sctp.Listen("sctp", "127.0.0.1:33334")
	if err != nil {
		panic(err)
	}

	b := make([]byte, 1024*1024)
	var nn int

	log.Printf("Accepting SCTP connections on %v ...", ln.Addr())
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				log.Println(err)
				return
			}
			rBuf, err := c.(*sctp.SCTPConn).GetReadBuffer()
			if err != nil {
				log.Println(err)
				return
			}
			wBuf, err := c.(*sctp.SCTPConn).GetWriteBuffer()
			if err != nil {
				log.Println(err)
				return
			}
			log.Printf("Accepted SCTP connection from %v, read/write buffer sizes: %d/%d", c.RemoteAddr(), rBuf, wBuf)

			nn = 0
			for {
				n, _, _, err := c.(*sctp.SCTPConn).ReadMsg(b)
				//n, err := c.Read(b)
				if err != nil && err != io.EOF {
					log.Println(err)
					break
				}
				nn += n
				if err == io.EOF {
					log.Printf("Received %d bytes", nn)
					break
				}
			}
			_ = c.Close()
		}
	}()

	// shutdown hook
	shutdownChan := make(chan os.Signal, 1) // channel is buffered to ensure signal sending before receiving it will not cause a deadlock
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)
	<-shutdownChan // block until signal is received
	ln.Close()
}
