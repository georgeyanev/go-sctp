//go:build linux

package sctp

import (
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"runtime"
	"syscall"
)

const (
	SOL_SCTP = 132

	SCTP_SOCKOPT_BINDX_ADD = 100
	SCTP_SOCKOPT_BINDX_REM = 101
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

// TODO: revise usage of Context in listening
// TODO: Add test from net.tcpsock_test.go and tcpsock_unix_test.go
// TODO: Add test from net.net_test.go (regarding Closing, Close read, close write etc)
// TODO: Add test from net.protoconn_test.go (regarding specific methods of Conn, SCTPConn etc)
// TODO: Add test from timeout_test.go
// TODO: Add test from write_unix_test.go
// TODO: Add test from conn_test.go
// TODO: Add test from dial_unix_test.go

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

func getBlockedState(fd int) string {
	flags, err := unix.FcntlInt(uintptr(fd), syscall.F_GETFL, 0)
	if err != nil {
		log.Fatalf("Failed to get file flags: %v", err)
	}

	// Check if O_NONBLOCK is set
	if flags&syscall.O_NONBLOCK != 0 {
		return "NON-blocked"
	} else {
		return "blocked"
	}
}
