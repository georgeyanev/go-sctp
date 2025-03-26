// Copyright (c) 2024 George Yanev
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

//go:build linux

package sctp

import (
	"context"
	"net"
	"time"
)

// DialSCTPContext acts like DialContext taking SCTP addresses and returning a SCTPConn.
func (d *Dialer) DialSCTPContext(ctx context.Context, network string, raddr *SCTPAddr) (*SCTPConn, error) {
	if ctx == nil {
		panic("nil context")
	}

	switch network {
	case "sctp", "sctp4", "sctp6":
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Source: nil, Addr: raddr.opAddr(), Err: net.UnknownNetworkError(network)}
	}

	deadline := d.deadline(ctx, time.Now())
	if !deadline.IsZero() {
		testHookStepTime()
		if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
			subCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			ctx = subCtx
		}
	}

	// check context done
	select {
	case <-ctx.Done():
		return nil, &net.OpError{Op: "dial", Net: network, Source: d.LocalAddr.opAddr(), Addr: raddr.opAddr(), Err: ctx.Err()}
	default:
	}

	if h := testHookDialSCTP; h != nil {
		return h(ctx, network, raddr, d)
	}

	return dialSCTP(ctx, network, raddr, d)
}

func dialSCTP(ctx context.Context, network string, raddr *SCTPAddr, d *Dialer) (*SCTPConn, error) {
	fd, err := clientSocket(ctx, network, raddr, d)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Source: d.LocalAddr.opAddr(), Addr: raddr.opAddr(), Err: err}
	}

	return newSCTPConn(fd, d.InitOptions.Heartbeat), nil
}
