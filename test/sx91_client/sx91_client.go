package main

import (
	"errors"
	"flag"
	"github.com/georgeyanev/go-sctp"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"time"
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

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	//  go run client.go  --addr localhost:3868 --clients 4 --count 10000 --network tcp

	addr := flag.String("addr", "localhost:3868", "address in form of ip:port to connect to")
	benchCli := flag.Int("clients", 1, "number of client connections")
	benchMsgs := flag.Int("count", 1000, "number of ACR messages to send")
	networkType := flag.String("network", "tcp", "protocol type tcp/sctp")
	drainMode := flag.Int("drain-mode", 0, "Drain incoming messages mode (0 - disable, 1 - sync, 2 - async)")

	flag.Parse()
	if len(*addr) == 0 {
		flag.Usage()
	}

	connect := func() (net.Conn, error) {
		return dial(*networkType, *addr)
	}

	done := make(chan int, 16)

	benchmark(connect, *benchCli, *benchMsgs, *drainMode, done)
}

func dial(network, addr string) (net.Conn, error) {
	switch network {
	case "sctp", "sctp4", "sctp6":
		sctpAddr, err := sctp.ResolveSCTPAddr(network, addr)
		if err != nil {
			return nil, err
		}

		return sctp.DialSCTP(network, nil, sctpAddr)
	case "tcp", "tcp4", "tcp6":
		tcpAddr, err := net.ResolveTCPAddr(network, addr)
		if err != nil {
			return nil, err
		}

		return net.DialTCP(network, nil, tcpAddr)
	}

	return nil, net.UnknownNetworkError(network)
}

type dialFunc func() (net.Conn, error)

func sender(conn net.Conn, msgs int, drainMode bool, done chan int) {
	rdbuf := make([]byte, 4096)
	total := 0

	payload := make([]byte, 1024)
	_, _ = rand.Read(payload)

	for i := 0; i < msgs; i += 1 {
		n, err := conn.Write(payload)
		if err != nil {
			log.Fatal(err)
		} else if n != len(payload) {
			log.Fatal("not all bytes written")
		}

		if !drainMode {
			if done != nil {
				done <- 1
			}

			continue
		}

		// drain
		received := 0

	drain:
		for {
			n, err := conn.Read(rdbuf[total:])

			if err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
					log.Printf("connection closed")
					return
				}

				log.Fatalf("read error: %v", err)

			}

			total += n

			if total < 1024 {
				continue
			}

			for total >= 1024 {
				total = copy(rdbuf, rdbuf[1024:total])
				received++
			}

			break drain
		}

		if done != nil && received > 0 {
			done <- received
		}
	}
}

func receiver(conn net.Conn, done chan int) {
	rdbuf := make([]byte, 16384)
	total := 0

	for {
		n, err := conn.Read(rdbuf[total:])

		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				log.Printf("connection closed")
				return
			}

			log.Fatalf("read error: %v", err)
		}

		total += n

		received := 0

		for total >= 1024 {
			total = copy(rdbuf, rdbuf[1024:total])
			received++
		}

		if received > 0 {
			done <- received
		}
	}
}

func benchmark(df dialFunc, ncli, msgs int, drainMode int, done chan int) {
	var err error
	c := make([]net.Conn, ncli)
	log.Println("Connecting", ncli, "clients...")
	for i := 0; i < ncli; i++ {
		c[i], err = df() // Dial and do CER/CEA handshake.
		if err != nil {
			log.Fatal(err)
		}
		defer c[i].Close()
	}
	log.Println("Done. Sending messages...")
	start := time.Now()
	for _, cli := range c {
		switch drainMode {
		case 0:
			go sender(cli, msgs, false, done)
		case 1:
			go sender(cli, msgs, true, done)
		case 2:
			go sender(cli, msgs, false, nil)
			go receiver(cli, done)
		}
	}

	count := 0
	total := ncli * msgs
wait:
	for {
		select {
		case n := <-done:
			count += n
			if count == total {
				break wait
			}
		case <-time.After(100 * time.Second):
			log.Fatal("Timeout waiting for messages.")
		}
	}
	elapsed := time.Since(start)
	log.Printf("%d messages in %s: %d/s", count, elapsed,
		int(float64(count)/elapsed.Seconds()))
}
