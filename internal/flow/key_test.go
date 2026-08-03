package flow

import (
	"net/netip"
	"testing"

	"github.com/sthorne/network-monitor/internal/capture"
)

func ev(src, dst string, sport, dport uint16) *capture.PacketEvent {
	return &capture.PacketEvent{
		Proto: capture.ProtoTCP,
		Src:   netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst),
		SrcPort: sport, DstPort: dport,
	}
}

func TestKeyCanonicalSymmetry(t *testing.T) {
	cases := [][2]*capture.PacketEvent{
		{ev("10.0.0.5", "93.184.216.34", 52104, 443), ev("93.184.216.34", "10.0.0.5", 443, 52104)},
		{ev("2001:db8::1", "2001:db8::2", 1000, 2000), ev("2001:db8::2", "2001:db8::1", 2000, 1000)},
		{ev("127.0.0.1", "127.0.0.1", 40000, 8080), ev("127.0.0.1", "127.0.0.1", 8080, 40000)},
	}
	for _, c := range cases {
		k1, d1 := KeyFromEvent(c[0])
		k2, d2 := KeyFromEvent(c[1])
		if k1 != k2 {
			t.Errorf("keys differ for reversed directions: %+v vs %+v", k1, k2)
		}
		if d1 == d2 {
			t.Errorf("directions should differ, both %v", d1)
		}
	}
}

func TestKeyDirEndpoint(t *testing.T) {
	e := ev("10.0.0.5", "1.1.1.1", 40000, 443)
	k, d := KeyFromEvent(e)
	addr, port := k.Endpoint(d)
	if addr != e.Src || port != e.SrcPort {
		t.Errorf("Endpoint(dir) = %v:%d, want packet source %v:%d", addr, port, e.Src, e.SrcPort)
	}
	addr, port = k.Endpoint(d.Reverse())
	if addr != e.Dst || port != e.DstPort {
		t.Errorf("Endpoint(reverse) = %v:%d, want packet dest %v:%d", addr, port, e.Dst, e.DstPort)
	}
}

func TestKeyICMPEcho(t *testing.T) {
	req := &capture.PacketEvent{
		Proto: capture.ProtoICMPv4,
		Src:   netip.MustParseAddr("10.0.0.5"), Dst: netip.MustParseAddr("8.8.8.8"),
		ICMPType: 8, ICMPID: 1234,
	}
	rep := &capture.PacketEvent{
		Proto: capture.ProtoICMPv4,
		Src:   netip.MustParseAddr("8.8.8.8"), Dst: netip.MustParseAddr("10.0.0.5"),
		ICMPType: 0, ICMPID: 1234,
	}
	k1, _ := KeyFromEvent(req)
	k2, _ := KeyFromEvent(rep)
	if k1 != k2 {
		t.Errorf("echo request/reply should share a key: %+v vs %+v", k1, k2)
	}
}
