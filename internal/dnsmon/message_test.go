package dnsmon

import (
	"testing"
)

// buildMsg assembles a DNS message: header fields plus one question.
func buildMsg(id uint16, flags uint16, name string, qtype uint16) []byte {
	b := []byte{byte(id >> 8), byte(id), byte(flags >> 8), byte(flags), 0, 1, 0, 0, 0, 0, 0, 0}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			b = append(b, byte(i-start))
			b = append(b, name[start:i]...)
			start = i + 1
		}
	}
	b = append(b, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return b
}

func TestParseQuery(t *testing.T) {
	buf := buildMsg(0x1234, 0x0100, "www.Example.COM", 28)
	m, ok := Parse(buf, false)
	if !ok {
		t.Fatal("parse failed")
	}
	if m.ID != 0x1234 || m.Response || !m.RD || m.Opcode != 0 {
		t.Errorf("header = %+v", m)
	}
	if m.QName != "www.example.com" {
		t.Errorf("qname = %q, want lower-cased www.example.com", m.QName)
	}
	if m.QType != 28 || m.QClass != 1 {
		t.Errorf("qtype/qclass = %d/%d, want 28/1", m.QType, m.QClass)
	}
}

func TestParseResponse(t *testing.T) {
	buf := buildMsg(0xbeef, 0x8183, "missing.example.com", 1) // QR|RD|RA, rcode 3
	buf[7] = 0                                                // ancount stays 0
	m, ok := Parse(buf, false)
	if !ok {
		t.Fatal("parse failed")
	}
	if !m.Response || m.RCode != 3 || !m.RA {
		t.Errorf("response header = %+v, want QR + NXDOMAIN + RA", m)
	}
}

func TestParseTCPPrefix(t *testing.T) {
	inner := buildMsg(0x0102, 0x0100, "example.org", 2)
	buf := append([]byte{byte(len(inner) >> 8), byte(len(inner))}, inner...)
	m, ok := Parse(buf, true)
	if !ok || m.QName != "example.org" {
		t.Fatalf("tcp parse = %+v ok=%v", m, ok)
	}
	if _, ok := Parse([]byte{0, 4, 1, 2, 3, 4}, true); ok {
		t.Error("accepted TCP message with impossible length prefix")
	}
}

func TestParseCompressionPointer(t *testing.T) {
	base := buildMsg(1, 0x8180, "a.example.net", 1)

	// A name that is a pointer to itself must fail cleanly, not hang.
	loop := append(base[:12:12], 0xc0, 12, 0, 1, 0, 1)
	if _, ok := Parse(loop, false); ok {
		t.Error("accepted self-referential compression pointer")
	}

	// A label followed by a pointer to a normal name must resolve.
	// Layout: header(12) | "www"(12..15) ptr(16..17) | qtype/qclass(18..21) |
	// "example.net"(22...). A forward pointer is unusual but legal wire.
	msg := append(base[:12:12], 3, 'w', 'w', 'w', 0xc0, 22, 0, 1, 0, 1)
	msg = append(msg, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'n', 'e', 't', 0)
	m, ok := Parse(msg, false)
	if !ok || m.QName != "www.example.net" {
		t.Errorf("pointer name = %+v ok=%v, want www.example.net", m, ok)
	}
	if m.QType != 1 || m.QClass != 1 {
		t.Errorf("qtype/qclass after pointer = %d/%d, want 1/1", m.QType, m.QClass)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	cases := [][]byte{
		nil,
		{1, 2, 3},
		// opcode 7 (reserved)
		{0, 1, 0x38, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
		// qdcount 9000
		{0, 1, 0, 0, 0x23, 0x28, 0, 0, 0, 0, 0, 0},
		// question runs past the buffer
		buildMsg(1, 0, "example.com", 1)[:14],
	}
	for i, c := range cases {
		if _, ok := Parse(c, false); ok {
			t.Errorf("case %d: accepted garbage %v", i, c)
		}
	}
}

func TestParseZeroQuestions(t *testing.T) {
	buf := []byte{0xab, 0xcd, 0x81, 0x82, 0, 0, 0, 0, 0, 0, 0, 0} // SERVFAIL, qd=0
	m, ok := Parse(buf, false)
	if !ok || m.QName != "" || m.RCode != 2 {
		t.Errorf("qd=0 parse = %+v ok=%v, want ok with empty qname", m, ok)
	}
}

func TestNames(t *testing.T) {
	if TypeName(1) != "A" || TypeName(28) != "AAAA" || TypeName(65) != "HTTPS" {
		t.Error("common type names wrong")
	}
	if TypeName(9999) != "TYPE9999" {
		t.Errorf("unknown type = %q", TypeName(9999))
	}
	if RCodeName(0) != "NOERROR" || RCodeName(3) != "NXDOMAIN" {
		t.Error("common rcode names wrong")
	}
	if RCodeName(14) != "RCODE14" {
		t.Errorf("unknown rcode = %q", RCodeName(14))
	}
}
