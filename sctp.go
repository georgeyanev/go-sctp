//go:build linux

package sctp

import (
	"fmt"
	"runtime"
)

// TODO: Add test from net.tcpsock_test.go and tcpsock_unix_test.go
// TODO: Add test from net.net_test.go (regarding Closing, Close read, close write etc)
// TODO: Add test from net.protoconn_test.go (regarding specific methods of Conn, SCTPConn etc)
// TODO: Add test from timeout_test.go
// TODO: Add test from write_unix_test.go
// TODO: Add test from conn_test.go
// TODO: Add test from dial_unix_test.go
// TODO: Test for timeouts with Accept (setReadDeadLine)
// TODO: Set finalizer for sctpFD?

func getGoroutineID() uint64 {
	buf := make([]byte, 64)
	n := runtime.Stack(buf, false)
	buf = buf[:n]
	// The format will look like "goroutine 1234 [running]:"
	var id uint64
	fmt.Sscanf(string(buf), "goroutine %d ", &id)
	return id
}
