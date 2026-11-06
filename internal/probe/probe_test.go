package probe

import (
	"encoding/binary"
	"testing"
)

func TestInnerIDSeq(t *testing.T) {
	// IPv4 header (20 bytes) + 8 bytes of the original ICMP echo.
	data := make([]byte, 28)
	data[0] = 0x45
	binary.BigEndian.PutUint16(data[20+4:20+6], 0xbeef)
	binary.BigEndian.PutUint16(data[20+6:20+8], 7)

	id, seq, ok := innerIDSeq(data)
	if !ok {
		t.Fatal("expected ok")
	}
	if id != 0xbeef || seq != 7 {
		t.Fatalf("id=%#x seq=%d", id, seq)
	}
}

func TestInnerIDSeqTooShort(t *testing.T) {
	if _, _, ok := innerIDSeq(make([]byte, 10)); ok {
		t.Fatal("expected false")
	}
}

func TestInnerIDSeqWithOptions(t *testing.T) {
	// IHL = 6 (24 bytes) to make sure we honour the header length.
	data := make([]byte, 32)
	data[0] = 0x46
	binary.BigEndian.PutUint16(data[24+4:24+6], 1)
	binary.BigEndian.PutUint16(data[24+6:24+8], 2)

	id, seq, ok := innerIDSeq(data)
	if !ok || id != 1 || seq != 2 {
		t.Fatalf("ok=%v id=%d seq=%d", ok, id, seq)
	}
}
