//go:build linux

package sctp

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestDialFailureClosesOnlyItsOwnDescriptor checks that a dial which fails after its
// socket was registered with the poller releases that socket exactly once.
//
// connect wraps the connecting socket in an os.File (fd.init) and closes that file when
// the connect fails, which frees the descriptor number. Closing the raw number again in
// clientSocket then hits whatever the kernel has since handed that number to. Here that
// is a pipe another goroutine is in the middle of using, so the stray close shows up as
// EBADF, or as the pipe's byte going missing.
//
// Run against a version with the double close:
//
//	go test -run TestDialFailureClosesOnlyItsOwnDescriptor -count=1 .
//	--- FAIL: TestDialFailureClosesOnlyItsOwnDescriptor
//	    dial_close_test.go:91: 42 descriptors owned by other goroutines were closed by 200 failed dials
func TestDialFailureClosesOnlyItsOwnDescriptor(t *testing.T) {
	// A port nothing listens on: bind one, read it back, release it. Every dial to it
	// goes EINPROGRESS and is then refused, which is the path that closed twice.
	ln, err := Listen("sctp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping, cannot listen on sctp: %v", err)
	}
	raddr := ln.Addr().(*SCTPAddr)
	ln.Close()

	const dials = 200

	var (
		wg     sync.WaitGroup
		stop   = make(chan struct{})
		broken int64 // descriptors that stopped working while their owner held them
	)

	// Victims: keep allocating descriptors and using them at once. A descriptor that
	// fails between its creation and its close was closed by someone else. The pipes
	// are non-blocking so a byte that went to the wrong pipe is EAGAIN, not a hang.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var p [2]int
			var b [1]byte
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := unix.Pipe2(p[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
					t.Error(err)
					return
				}
				_, werr := unix.Write(p[1], []byte{1})
				_, rerr := unix.Read(p[0], b[:])
				if werr != nil || rerr != nil {
					// Do not close: one of these numbers may now belong to somebody else.
					atomic.AddInt64(&broken, 1)
					continue
				}
				unix.Close(p[0])
				unix.Close(p[1])
			}
		}()
	}

	d := Dialer{Timeout: 5 * time.Second}
	for i := 0; i < dials; i++ {
		c, err := d.DialSCTP("sctp", raddr)
		if err == nil {
			c.Close()
			t.Fatalf("dial %d to a port nothing listens on succeeded", i)
		}
	}

	close(stop)
	wg.Wait()

	if n := atomic.LoadInt64(&broken); n != 0 {
		t.Fatalf("%d descriptors owned by other goroutines were closed by %d failed dials", n, dials)
	}
}
