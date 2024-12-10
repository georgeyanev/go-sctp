//go:build linux

package main

import (
	"errors"
	"flag"
	"github.com/georgeyanev/go-sctp"
	"io"
	"log"
	"net"
	_ "net/http/pprof"
	"os"
	"syscall"
)

// Try running these examples as follows:
//
//
// 1. Server in echo mode, client in sync drain-mode:
//
// $ ./sx91_server --addr 127.0.0.1:3868 --network sctp --echo
// $ ./sx91_client --addr 127.0.0.1:3868 --network sctp --clients 1 --count 100000 --drain-mode 1
//
//
// 2. Server in echo mode, client in async drain-mode:
//
// $ ./sx91_server --addr 127.0.0.1:3868 --network sctp --echo
// $ ./sx91_client --addr 127.0.0.1:3868 --network sctp --clients 1 --count 100000 --drain-mode 2
//
//
// 3. Server in receive-only mode, client in send-only mode:
//
// $ ./sx91_server --addr 127.0.0.1:3868 --network sctp
// $ ./sx91_client --addr 127.0.0.1:3868 --network sctp --clients 1 --count 100000 --drain-mode 0

func main() {
	// go run server.go --addr=localhost:3867 --network=tcp

	addr := flag.String("addr", ":3868", "address in the form of ip:port to listen on")
	networkType := flag.String("network", "tcp", "protocol type tcp/sctp")
	echoMode := flag.Bool("echo", false, "Send back incoming messages")
	flag.Parse()

	err := listen(*networkType, *addr, *echoMode)
	if err != nil {
		log.Fatal(err)
	}
}

func listen(network, addr string, echoMode bool) error {
	log.Println("Starting server on", addr)

	var listener net.Listener

	switch network {
	case "sctp", "sctp4", "sctp6":
		sctpAddr, err := sctp.ResolveSCTPAddr(network, addr)
		if err != nil {
			return err
		}

		sctpListener, err := sctp.ListenSCTP(network, sctpAddr)
		if err != nil {
			return err
		}

		listener = sctpListener
	case "tcp", "tcp4", "tcp6":
		tcpAddr, err := net.ResolveTCPAddr(network, addr)
		if err != nil {
			return err
		}

		tcpListener, err := net.ListenTCP(network, tcpAddr)
		if err != nil {
			return err
		}

		listener = tcpListener
	}

	log.Printf("start listening on %s://%s", network, addr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal("dead listener")
		}

		log.Printf("accepted incoming connection")

		go reader(conn, echoMode)
	}

}

func reader(conn net.Conn, echoMode bool) {
	buf := make([]byte, 4096)
	total := 0
	totalPackets := 0

	for {
		n, err := conn.Read(buf[total:])

		if err != nil {
			log.Printf("read error: %v (processed %d packets)", err, totalPackets)

			if errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				log.Printf("connection closed")
				return
			}

			return
		}

		if echoMode {
			total += n

			for total >= 1024 {
				payload := buf[:1024]
				wn, err := conn.Write(payload)
				if err != nil {
					log.Printf("write error: %v (processed %d packets)", err, totalPackets)
					if errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, os.ErrClosed) {
						return
					}
					return
				}

				if wn != len(payload) {
					log.Fatal("not all bytes written")
				}

				total = copy(buf, buf[1024:total])

				totalPackets++
			}
		}
	}
}
