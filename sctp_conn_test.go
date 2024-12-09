//go:build linux

package sctp

import "testing"

func TestHtonui32Ntohui32(t *testing.T) {
	var a uint32 = 0x01020304
	b := Htonui32(Ntohui32(a))
	if a != b {
		t.Fatalf("Htonui32(Ntohui32(a)) = %d, want %d", b, a)
	}
	b = Ntohui32(Htonui32(a))
	if a != b {
		t.Fatalf("Htonui32(Ntohui32(a)) = %d, want %d", b, a)
	}
}

func TestHtonui16Ntohui16(t *testing.T) {
	var a uint16 = 0x0102
	b := Htonui16(Ntohui16(a))
	if a != b {
		t.Fatalf("Htonui16(Ntohui16(a)) = %d, want %d", b, a)
	}
	b = Ntohui16(Htonui16(a))
	if a != b {
		t.Fatalf("Htonui16(Ntohui16(a)) = %d, want %d", b, a)
	}
}
