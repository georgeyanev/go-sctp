package sctp

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"testing"
)

// Test AssocChange even
func TestAssocChangeEvent(t *testing.T) {
	ln1, err := Listen("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	err = ln1.(*SCTPListener).Subscribe(SCTP_ASSOC_CHANGE)
	if err != nil {
		t.Fatal(err)
	}

	closeChan := make(chan struct{})
	errorChan := make(chan error)
	go func() {
		c, err1 := ln1.Accept()
		if err1 != nil {
			errorChan <- err1
			return
		}
		defer func(c net.Conn) {
			c.Close()
			close(closeChan)
		}(c)

		c1 := c.(*SCTPConn)

		b := make([]byte, 256)

		// receive AssocChange event with SCTP_COMM_UP state
		n, rcvInfo, recvFlags, err1 := c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		if (recvFlags & SCTP_NOTIFICATION) != SCTP_NOTIFICATION {
			errorChan <- errors.New("expected SCTP_ASSOC_CHANGE event")
			return
		}
		if (recvFlags & SCTP_EOR) != SCTP_EOR {
			errorChan <- errors.New("expected whole message")
			return
		}
		if rcvInfo != nil {
			errorChan <- errors.New("expected nil rcvInfo")
			return
		}

		e, err1 := ParseEvent(b[:n])
		if err1 != nil {
			errorChan <- err1
			return
		}

		ace, ok := e.(*AssocChangeEvent)
		if !ok {
			errorChan <- errors.New("expected AssocChangeEvent")
			return
		}
		if ace.State != SCTP_COMM_UP {
			errorChan <- errors.New("expected SCTP_COMM_UP")
			return
		}

		// receive data
		n, rcvInfo, recvFlags, err1 = c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		if (recvFlags & SCTP_NOTIFICATION) == SCTP_NOTIFICATION {
			errorChan <- errors.New("expected data message")
			return
		}
		if (recvFlags & SCTP_EOR) != SCTP_EOR {
			errorChan <- errors.New("expected whole message")
			return
		}
		if rcvInfo == nil {
			errorChan <- errors.New("expected non-nil rcvInfo")
			return
		}
		if !bytes.Equal(b[:n], []byte("hello")) {
			errorChan <- errors.New("expected 'hello'")
			return
		}

		// receive AssocChange event with SCTP_SHUTDOWN_COMP state
		n, rcvInfo, recvFlags, err1 = c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		if (recvFlags & SCTP_NOTIFICATION) != SCTP_NOTIFICATION {
			errorChan <- errors.New("expected SCTP_ASSOC_CHANGE event")
			return
		}
		if (recvFlags & SCTP_EOR) != SCTP_EOR {
			errorChan <- errors.New("expected whole message")
			return
		}
		if rcvInfo != nil {
			errorChan <- errors.New("expected nil rcvInfo")
			return
		}

		e, err1 = ParseEvent(b[:n])
		if err1 != nil {
			errorChan <- err1
			return
		}

		ace, ok = e.(*AssocChangeEvent)
		if !ok {
			errorChan <- errors.New("expected AssocChangeEvent")
			return
		}
		if ace.State != SCTP_SHUTDOWN_COMP {
			errorChan <- errors.New("expected SCTP_SHUTDOWN_COMP")
			return
		}

		// subsequent reads from association should return EOF
		n, rcvInfo, recvFlags, err1 = c1.ReadMsg(b)
		if err1 == nil || err1 != io.EOF {
			errorChan <- errors.New("expected EOF")
			return
		}
	}()

	c, err := Dial("sctp4", ln1.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	_, err = c.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	select {
	case <-closeChan:
	case err := <-errorChan:
		if err != io.EOF {
			t.Fatal(err)
		}
	}
}

// For this test to work, the kernel parameters `net.sctp.addip_enable`
// and `net.sctp.addip_noauth_enable` must be set to 1.
func TestPeerAddrChangeEvent(t *testing.T) {
	ln1, err := Listen("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	closeChan := make(chan struct{})
	errorChan := make(chan error)
	go func() {
		c, err1 := ln1.Accept()
		if err1 != nil {
			errorChan <- err1
			return
		}
		defer func(c net.Conn) {
			c.Close()
			close(closeChan)
		}(c)

		c1 := c.(*SCTPConn)
		err1 = c1.Subscribe(SCTP_PEER_ADDR_CHANGE)
		if err1 != nil {
			errorChan <- err1
			return
		}

		b := make([]byte, 256)

		// receive data
		log.Println("Reading 1...")
		n, _, recvFlags, err1 := c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		c1.RefreshRemoteAddr()
		log.Printf("Reading 1..., raddr: %s", c1.RemoteAddr().String())
		log.Println("Reading 1... done")
		if (recvFlags & SCTP_NOTIFICATION) == SCTP_NOTIFICATION {
			errorChan <- errors.New("expected data message")
			return
		}
		if (recvFlags & SCTP_EOR) != SCTP_EOR {
			errorChan <- errors.New("expected whole message")
			return
		}
		if !bytes.Equal(b[:n], []byte("hello")) {
			errorChan <- errors.New("expected equal 'hello', got: " + string(b[:n]))
			return
		}
		_, err1 = c1.Write([]byte("yes"))
		if err1 != nil {
			errorChan <- err1
			return
		}

		// receive peer addr change event
		c1.RefreshRemoteAddr()
		log.Printf("Reading 2..., raddr: %s", c1.RemoteAddr().String())
		n, _, recvFlags, err1 = c1.ReadMsg(b)
		if err1 != nil {
			errorChan <- err1
			return
		}
		log.Println("Reading 2... done")

		if (recvFlags & SCTP_NOTIFICATION) != SCTP_NOTIFICATION {
			errorChan <- errors.New("expected SCTP_PEER_ADDR_CHANGE event")
			return
		}
		if (recvFlags & SCTP_EOR) != SCTP_EOR {
			errorChan <- errors.New("expected whole message")
			return
		}

		e, err1 := ParseEvent(b[:n])
		if err1 != nil {
			errorChan <- err1
			return
		}

		pace, ok := e.(*PeerAddrChangeEvent)
		if !ok {
			errorChan <- errors.New("expected PeerAddrChangeEvent")
			return
		}
		if pace.State != SCTP_ADDR_ADDED {
			errorChan <- errors.New("expected SCTP_ADDR_ADDED")
			return
		}
		if pace.Addr.String() != "127.0.0.2" {
			errorChan <- errors.New("expected 127.0.0.2 address to be added")
			return
		}
	}()

	var d = Dialer{
		LocalAddr: &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IP{127, 0, 0, 1}}}},
	}
	c, err := d.Dial("sctp4", ln1.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Dial: %s ------> %s", c.LocalAddr().String(), c.RemoteAddr().String())
	_, err = c.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 8)
	n, err1 := c.Read(b)
	if err1 != nil {
		t.Fatal(err1)
	}
	if !bytes.Equal(b[:n], []byte("yes")) {
		errorChan <- errors.New("expected equal 'yes', got: " + string(b[:n]))
		return
	}

	err = c.(*SCTPConn).BindAdd("127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-closeChan:
	case err = <-errorChan:
		if err != io.EOF {
			t.Fatal(err)
		}
	}
	c.Close()
}

func TestRemoteErrorEvent(t *testing.T) {
	ln1, err := Listen("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	closeChan := make(chan struct{})
	errorChan := make(chan error)
	go func() {
		c, err1 := ln1.Accept()
		if err1 != nil {
			errorChan <- err1
			return
		}
		defer func(c net.Conn) {
			c.Close()
			close(closeChan)
		}(c)

		c1 := c.(*SCTPConn)
		err1 = c1.Subscribe(SCTP_PEER_ADDR_CHANGE, SCTP_REMOTE_ERROR)
		if err1 != nil {
			errorChan <- err1
			return
		}

		b := make([]byte, 256)

		sndInfo := SndInfo{Sid: 9}
		_, err := c1.WriteMsg([]byte("hello"), &sndInfo)
		if err != nil {
			errorChan <- err1
			return
		}

		// receive data
		for {
			log.Println("Reading ...")
			n, _, recvFlags, err1 := c1.ReadMsg(b)
			if err1 != nil {
				errorChan <- err1
				return
			}
			log.Println("Reading ... done")
			if (recvFlags & SCTP_NOTIFICATION) == SCTP_NOTIFICATION {
				log.Println("Notification is received, about to parse")
				e, err1 := ParseEvent(b[:n])
				if err1 != nil {
					errorChan <- err1
					return
				}
				log.Printf("Notification parsed: %v", e)
			} else {
				log.Printf("Data is received: %s", string(b[:n]))
			}
		}
	}()

	var d = Dialer{
		LocalAddr: &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IP{127, 0, 0, 1}}}},
	}
	c, err := d.Dial("sctp4", ln1.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Dial: %s ------> %s", c.LocalAddr().String(), c.RemoteAddr().String())
	_, err = c.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 8)
	_, err1 := c.Read(b)
	if err1 != nil {
		t.Fatal(err1)
	}

	c.Close()
	select {
	case <-closeChan:
	case err = <-errorChan:
		if err != io.EOF {
			t.Fatal(err)
		}
	}
}

func TestShutdownEvent(t *testing.T) {
	ln1, err := Listen("sctp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	closeChan := make(chan struct{})
	errorChan := make(chan error)
	go func() {
		c, err1 := ln1.Accept()
		if err1 != nil {
			errorChan <- err1
			return
		}
		defer func(c net.Conn) {
			c.Close()
			close(closeChan)
		}(c)

		c1 := c.(*SCTPConn)
		err1 = c1.Subscribe(SCTP_PEER_ADDR_CHANGE, SCTP_REMOTE_ERROR)
		if err1 != nil {
			errorChan <- err1
			return
		}

		b := make([]byte, 256)

		sndInfo := SndInfo{Sid: 9}
		_, err := c1.WriteMsg([]byte("hello"), &sndInfo)
		if err != nil {
			errorChan <- err1
			return
		}

		// receive data
		for {
			log.Println("Reading ...")
			n, _, recvFlags, err1 := c1.ReadMsg(b)
			if err1 != nil {
				errorChan <- err1
				return
			}
			log.Println("Reading ... done")
			if (recvFlags & SCTP_NOTIFICATION) == SCTP_NOTIFICATION {
				log.Println("Notification is received, about to parse")
				e, err1 := ParseEvent(b[:n])
				if err1 != nil {
					errorChan <- err1
					return
				}
				log.Printf("Notification parsed: %v", e)
			} else {
				log.Printf("Data is received: %s", string(b[:n]))
			}
		}
	}()

	var d = Dialer{
		LocalAddr: &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IP{127, 0, 0, 1}}}},
	}
	c, err := d.Dial("sctp4", ln1.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Dial: %s ------> %s", c.LocalAddr().String(), c.RemoteAddr().String())
	_, err = c.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 8)
	_, err1 := c.Read(b)
	if err1 != nil {
		t.Fatal(err1)
	}

	c.Close()
	select {
	case <-closeChan:
	case err = <-errorChan:
		if err != io.EOF {
			t.Fatal(err)
		}
	}
}
