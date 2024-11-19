package sctp

import (
	"fmt"
	"strings"
	"testing"
)

func TestListenerBindAddRemove(t *testing.T) {
	ln1, err := Listen("sctp4", "127.0.0.1/127.0.0.2/127.0.0.3/127.0.0.4:0")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("ln1 address before: ", ln1.Addr())
	ln1SCTP := ln1.(*SCTPListener)
	err = ln1SCTP.Binder().BindRemove("127.0.0.2/127.0.0.1:" + ln1SCTP.port())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ln1.Addr().String(), "127.0.0.1") ||
		strings.Contains(ln1.Addr().String(), "127.0.0.2") {
		t.Fatal(err)
	}
	fmt.Println("ln1 address after: ", ln1.Addr())
	err = ln1SCTP.Binder().BindAdd("127.0.0.2/127.0.0.1:" + ln1SCTP.port())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ln1.Addr().String(), "127.0.0.1") ||
		!strings.Contains(ln1.Addr().String(), "127.0.0.2") {
		t.Fatal(err)
	}
	fmt.Println("ln1 address after: ", ln1.Addr())
	_ = ln1.Close()

	//
	ln1, err = Listen("sctp", "[::1]/127.0.0.1/127.0.0.2/127.0.0.3/127.0.0.4:0")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("ln1 address before: ", ln1.Addr())
	ln1SCTP = ln1.(*SCTPListener)
	err = ln1SCTP.Binder().BindRemove("[::1]/127.0.0.2/127.0.0.1:" + ln1SCTP.port())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ln1.Addr().String(), "127.0.0.1") ||
		strings.Contains(ln1.Addr().String(), "127.0.0.2") ||
		strings.Contains(ln1.Addr().String(), "::1") {
		t.Fatal(err)
	}
	fmt.Println("ln1 address after: ", ln1.Addr())

	err = ln1SCTP.Binder().BindAdd("[::1]/127.0.0.2/127.0.0.1:" + ln1SCTP.port())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ln1.Addr().String(), "127.0.0.1") ||
		!strings.Contains(ln1.Addr().String(), "127.0.0.2") ||
		!strings.Contains(ln1.Addr().String(), "::1") {
		t.Fatal(err)
	}
	fmt.Println("ln1 address after: ", ln1.Addr())
	_ = ln1.Close()
}
