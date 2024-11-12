//go:build linux

package sctp

import (
	"fmt"
	"runtime"
)

const (
	SOL_SCTP = 132
)

// InitMsg structure provides information for initializing new SCTP associations
type InitMsg struct {
	// number of streams to which the application wishes to be able to send, 10 by default
	NumOstreams uint16
	// maximum number of inbound streams the application is prepared to support, 10 by default
	MaxInstreams uint16
	// how many attempts the SCTP endpoint should make at resending the INIT
	// if not specified the kernel parameter net.sctp.max_init_retransmits is used as default
	MaxAttempts uint16
	// largest timeout or retransmission timeout (RTO) value (in milliseconds) to use in attempting an INIT
	// if not specified the kernel parameter net.sctp.rto_max is used as default
	MaxInitTimeout uint16
}

// TODO: add dial tests - done with one test left for revisiting
// TODO: Add test from net.server_test.go (regarding concurrent accept-read-write servers)

// TODO: add more listener test (for control func and others (from net.listen_tests.go))
// TODO: revise usage of Context in listening
// TODO: rawBind refreshing addresses (maybe refresh from the exported functions)
// TODO: Add test from net.tcpsock_test.go and tcpsock_unix_test.go
// TODO: Add test from net.net_test.go (regarding Closing, Close read, close write etc)
// TODO: Add test from net.protoconn_test.go (regarding specific methods of Conn, SCTPConn etc)
// TODO: Add test from timeout_test.go
// TODO: Add test from write_unix_test.go
// TODO: Add test from conn_test.go
// TODO: Add test from dial_unix_test.go
// TODO: revisit TestCancelAfterDialSCTP

// )

func getGoroutineID() uint64 {
	buf := make([]byte, 64)
	n := runtime.Stack(buf, false)
	buf = buf[:n]
	// The format will look like "goroutine 1234 [running]:"
	var id uint64
	fmt.Sscanf(string(buf), "goroutine %d ", &id)
	return id
}
