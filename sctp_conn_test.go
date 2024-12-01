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
