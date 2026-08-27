package dnsmon

import (
	"strings"
	"testing"
)

// buildRR appends a resource record with the given wire rdata.
func buildRR(msg []byte, name []byte, typ uint16, ttl uint32, rdata []byte) []byte {
	msg = append(msg, name...)
	msg = append(msg, byte(typ>>8), byte(typ), 0, 1)
	msg = append(msg, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
	msg = append(msg, byte(len(rdata)>>8), byte(len(rdata)))
	return append(msg, rdata...)
}

func TestDecodeDetailFullResponse(t *testing.T) {
	// Header: response, RD|RA, NOERROR; qd=1 an=2 ns=1 ar=1(OPT).
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 1, 0, 1}
	msg = append(msg, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	ptr := []byte{0xc0, 12} // compressed pointer to the question name
	// CNAME www.example.com → example.com (pointer to offset 16).
	msg = buildRR(msg, ptr, 5, 300, []byte{0xc0, 16})
	// A example.com → 93.184.216.34.
	msg = buildRR(msg, []byte{0xc0, 16}, 1, 300, []byte{93, 184, 216, 34})
	// Authority: NS example.com → ns1.example.com.
	msg = buildRR(msg, []byte{0xc0, 16}, 2, 86400, append([]byte{3, 'n', 's', '1'}, 0xc0, 16))
	// Additional: OPT, udp 1232, DO.
	msg = buildRR(msg, []byte{0}, 41, 0x00008000, nil)
	msg[len(msg)-8], msg[len(msg)-7] = 0x04, 0xd0 // class field = udp size 1232

	d, ok := DecodeDetail(msg, false)
	if !ok {
		t.Fatal("decode failed")
	}
	if len(d.Questions) != 1 || d.Questions[0].Name != "www.example.com" || d.Questions[0].Type != 1 {
		t.Errorf("questions = %+v", d.Questions)
	}
	if len(d.Answers) != 2 {
		t.Fatalf("answers = %+v, want 2", d.Answers)
	}
	if d.Answers[0].Data != "example.com." || d.Answers[0].Name != "www.example.com" {
		t.Errorf("CNAME answer = %+v", d.Answers[0])
	}
	if d.Answers[1].Data != "93.184.216.34" || d.Answers[1].TTL != 300 {
		t.Errorf("A answer = %+v", d.Answers[1])
	}
	if len(d.Authority) != 1 || d.Authority[0].Data != "ns1.example.com." {
		t.Errorf("authority = %+v", d.Authority)
	}
	if len(d.Additional) != 0 {
		t.Errorf("additional should exclude OPT, got %+v", d.Additional)
	}
	if !d.EDNS.Present || d.EDNS.UDPSize != 1232 || !d.EDNS.DO {
		t.Errorf("edns = %+v", d.EDNS)
	}
	if d.Truncated {
		t.Error("unexpected Truncated")
	}
	if fs := d.FlagString(); fs != "qr rd ra" {
		t.Errorf("flags = %q, want 'qr rd ra'", fs)
	}
}

func TestDecodeDetailRDataRenderers(t *testing.T) {
	// One message per type: qd=0, an=1.
	mk := func(typ uint16, rdata []byte) MsgDetail {
		msg := []byte{0, 1, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0}
		msg = buildRR(msg, []byte{1, 'x', 0}, typ, 60, rdata)
		d, ok := DecodeDetail(msg, false)
		if !ok {
			t.Fatalf("type %d: decode failed", typ)
		}
		return d
	}
	if got := mk(15, append([]byte{0, 10, 4, 'm', 'a', 'i', 'l'}, 1, 'x', 0)).Answers[0].Data; got != "10 mail.x." {
		t.Errorf("MX = %q", got)
	}
	if got := mk(16, []byte{5, 'h', 'e', 'l', 'l', 'o'}).Answers[0].Data; got != `"hello"` {
		t.Errorf("TXT = %q", got)
	}
	if got := mk(28, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}).Answers[0].Data; got != "2001:db8::1" {
		t.Errorf("AAAA = %q", got)
	}
	if got := mk(33, append([]byte{0, 5, 0, 0, 1, 187, 3, 's', 'r', 'v'}, 1, 'x', 0)).Answers[0].Data; got != "5 0 443 srv.x." {
		t.Errorf("SRV = %q", got)
	}
	// Unknown type falls back to a hex preview.
	if got := mk(999, []byte{0xde, 0xad}).Answers[0].Data; got != `\# 2 dead` {
		t.Errorf("unknown = %q", got)
	}
}

func TestDecodeDetailTruncatedTail(t *testing.T) {
	msg := []byte{0, 1, 0x80, 0, 0, 1, 0, 5, 0, 0, 0, 0}
	msg = append(msg, 1, 'x', 0, 0, 1, 0, 1)
	// Claims 5 answers but carries none: decode keeps the question and flags
	// the truncation instead of failing.
	d, ok := DecodeDetail(msg, false)
	if !ok || !d.Truncated || len(d.Questions) != 1 {
		t.Errorf("truncated decode = %+v ok=%v", d, ok)
	}
}

func TestDecodeDetailTCP(t *testing.T) {
	inner := []byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	inner = append(inner, 1, 'a', 3, 'c', 'o', 'm', 0, 0, 16, 0, 1)
	buf := append([]byte{byte(len(inner) >> 8), byte(len(inner))}, inner...)
	d, ok := DecodeDetail(buf, true)
	if !ok || len(d.Questions) != 1 || d.Questions[0].Name != "a.com" {
		t.Errorf("tcp decode = %+v ok=%v", d, ok)
	}
}

func TestNameHelpers(t *testing.T) {
	if OpcodeName(0) != "QUERY" || OpcodeName(5) != "UPDATE" || OpcodeName(9) != "OPCODE9" {
		t.Error("opcode names wrong")
	}
	if ClassName(1) != "IN" || ClassName(255) != "ANY" || !strings.HasPrefix(ClassName(42), "CLASS") {
		t.Error("class names wrong")
	}
}
