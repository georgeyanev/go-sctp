package sctp

import (
	"fmt"
	"log"
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
	err = ln1SCTP.BindRemove("127.0.0.2/127.0.0.1:" + ln1SCTP.port())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ln1.Addr().String(), "127.0.0.1") ||
		strings.Contains(ln1.Addr().String(), "127.0.0.2") {
		t.Fatal(err)
	}
	fmt.Println("ln1 address after: ", ln1.Addr())
	err = ln1SCTP.BindAdd("127.0.0.2/127.0.0.1:" + ln1SCTP.port())
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
	err = ln1SCTP.BindRemove("[::1]/127.0.0.2/127.0.0.1:" + ln1SCTP.port())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ln1.Addr().String(), "127.0.0.1") ||
		strings.Contains(ln1.Addr().String(), "127.0.0.2") ||
		strings.Contains(ln1.Addr().String(), "::1") {
		t.Fatal(err)
	}
	fmt.Println("ln1 address after: ", ln1.Addr())

	err = ln1SCTP.BindAdd("[::1]/127.0.0.2/127.0.0.1:" + ln1SCTP.port())
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

func TestTemp(t *testing.T) {
	ln1, err := Listen("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	maxSeg, err := ln1.(*SCTPListener).fd.getMaxseg()
	if err != nil {
		log.Fatal(err)
	}

	disableFragments, err := ln1.(*SCTPListener).fd.getDisableFragments()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Maxseg on listener: %v", maxSeg)
	log.Printf("DisableFragments on listener: %v", disableFragments)

	closeChan := make(chan struct{})
	go func() {
		for {
			c, err := ln1.Accept()
			if err != nil {
				log.Fatal(err)
			}
			maxSeg2, err := c.(*SCTPConn).fd.getMaxseg()
			if err != nil {
				log.Fatal(err)
			}
			disableFragments2, err := c.(*SCTPConn).fd.getDisableFragments()
			if err != nil {
				log.Fatal(err)
			}

			sndBuf, err := c.(*SCTPConn).fd.getSendBuffer()
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Initial sendBuffer size: %v", sndBuf)

			err = c.(*SCTPConn).fd.setSendBuffer(1024 * 1024 * 10) // 10MB
			if err != nil {
				log.Fatal(err)
			}
			sndBuf, err = c.(*SCTPConn).fd.getSendBuffer()
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Final sendBuffer size: %v", sndBuf)

			log.Printf("Maxseg on accepted connection: %v", maxSeg2)
			log.Printf("DisabledFragments on accepted connection: %v", disableFragments2)
			c.Close()
			close(closeChan)
		}
	}()
	c, err := Dial("sctp4", ln1.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	maxSeg3, err := c.(*SCTPConn).fd.getMaxseg()
	if err != nil {
		log.Fatal(err)
	}
	disableFragments3, err := c.(*SCTPConn).fd.getDisableFragments()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Maxseg on dialed connection: %v", maxSeg3)
	log.Printf("DisabledFragments on dialed connection: %v", disableFragments3)

	<-closeChan
}
