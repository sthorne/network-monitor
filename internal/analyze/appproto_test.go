package analyze

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/sthorne/network-monitor/internal/capture"
)

// buildClientHello hand-encodes a minimal TLS ClientHello with SNI and ALPN.
func buildClientHello(sni, alpn string) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)             // client_version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0)                      // session_id length
	body = append(body, 0x00, 0x02, 0x13, 0x01) // one cipher suite
	body = append(body, 1, 0)                   // one compression method (null)

	var exts []byte
	if sni != "" {
		name := []byte(sni)
		entry := append([]byte{0}, u16(len(name))...) // host_name type + len
		entry = append(entry, name...)
		list := append(u16(len(entry)), entry...)
		exts = append(exts, u16(0)...) // extension type 0
		exts = append(exts, u16(len(list))...)
		exts = append(exts, list...)
	}
	if alpn != "" {
		p := []byte(alpn)
		entry := append([]byte{byte(len(p))}, p...)
		list := append(u16(len(entry)), entry...)
		exts = append(exts, u16(16)...) // extension type 16
		exts = append(exts, u16(len(list))...)
		exts = append(exts, list...)
	}
	body = append(body, u16(len(exts))...)
	body = append(body, exts...)

	hs := append([]byte{0x01, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x01}, u16(len(hs))...)
	return append(rec, hs...)
}

func u16(n int) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(n))
	return b
}

func TestSniffTLSClientHello(t *testing.T) {
	buf := buildClientHello("example.com", "h2")
	res, ok := Sniff(capture.ProtoTCP, 40000, 443, buf)
	if !ok || res.Name != "TLS" {
		t.Fatalf("Sniff = %+v ok=%v, want TLS", res, ok)
	}
	if !strings.Contains(res.Detail, "example.com") || !strings.Contains(res.Detail, "h2") {
		t.Errorf("detail = %q, want SNI and ALPN", res.Detail)
	}
}

func TestSniffTLSTruncated(t *testing.T) {
	buf := buildClientHello("very-long-hostname.example.com", "h2")
	for n := 0; n <= len(buf); n++ {
		res, ok := Sniff(capture.ProtoTCP, 40000, 443, buf[:n]) // must never panic
		if ok && res.Name != "TLS" {
			t.Fatalf("truncated ClientHello identified as %q", res.Name)
		}
	}
}

func TestSniffHTTP(t *testing.T) {
	res, ok := Sniff(capture.ProtoTCP, 40000, 8080, []byte("GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n"))
	if !ok || res.Name != "HTTP" {
		t.Fatalf("Sniff = %+v ok=%v, want HTTP", res, ok)
	}
	if res.Detail != "GET /index.html HTTP/1.1" {
		t.Errorf("detail = %q", res.Detail)
	}
}

func TestSniffSSH(t *testing.T) {
	res, ok := Sniff(capture.ProtoTCP, 40000, 22, []byte("SSH-2.0-OpenSSH_9.6\r\n"))
	if !ok || res.Name != "SSH" {
		t.Fatalf("Sniff = %+v ok=%v, want SSH", res, ok)
	}
}

func TestSniffDNS(t *testing.T) {
	// Header: id, flags(std query), qd=1, an/ns/ar=0, then www.example.com A IN.
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"www", "example", "com"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	res, ok := Sniff(capture.ProtoUDP, 54321, 53, q)
	if !ok || res.Name != "DNS" {
		t.Fatalf("Sniff = %+v ok=%v, want DNS", res, ok)
	}
	if res.Detail != "www.example.com" {
		t.Errorf("qname = %q", res.Detail)
	}
}

func TestSniffQUIC(t *testing.T) {
	buf := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08} // long header, version 1
	res, ok := Sniff(capture.ProtoUDP, 40000, 443, buf)
	if !ok || res.Name != "QUIC" {
		t.Fatalf("Sniff = %+v ok=%v, want QUIC", res, ok)
	}
}

func TestPortFallback(t *testing.T) {
	res := PortFallback(capture.ProtoTCP, 52104, 443)
	if res.Name != "https?" || !res.FromPort {
		t.Errorf("PortFallback = %+v, want https?", res)
	}
	if res := PortFallback(capture.ProtoTCP, 50000, 50001); res.Name != "" {
		t.Errorf("unknown ports returned %q", res.Name)
	}
}

func FuzzSniff(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1"))
	f.Add(buildClientHello("example.com", "h2"))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		Sniff(capture.ProtoTCP, 1234, 443, data)
		Sniff(capture.ProtoUDP, 1234, 53, data)
	})
}
