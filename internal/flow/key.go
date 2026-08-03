package flow

import (
	"net/netip"

	"github.com/sthorne/network-monitor/internal/capture"
)

// Dir distinguishes the two directions of a flow relative to its canonical
// key (A→B or B→A), not relative to client/server.
type Dir uint8

const (
	DirAtoB Dir = 0
	DirBtoA Dir = 1
)

func (d Dir) Reverse() Dir { return d ^ 1 }

// FlowKey is a canonical 5-tuple: endpoints are ordered by (address, port) so
// both directions of a conversation map to the same key. It is comparable and
// used directly as a map key.
type FlowKey struct {
	Proto        capture.Proto
	AddrA, AddrB netip.Addr
	PortA, PortB uint16
}

// KeyFromEvent canonicalizes an event's endpoints and reports which direction
// the packet travelled. ICMP echo flows use the echo identifier as the port so
// request and reply pair up.
func KeyFromEvent(ev *capture.PacketEvent) (FlowKey, Dir) {
	sport, dport := ev.SrcPort, ev.DstPort
	if ev.Proto == capture.ProtoICMPv4 || ev.Proto == capture.ProtoICMPv6 {
		sport, dport = ev.ICMPID, ev.ICMPID
	}
	c := ev.Src.Compare(ev.Dst)
	if c < 0 || (c == 0 && sport <= dport) {
		return FlowKey{Proto: ev.Proto, AddrA: ev.Src, AddrB: ev.Dst, PortA: sport, PortB: dport}, DirAtoB
	}
	return FlowKey{Proto: ev.Proto, AddrA: ev.Dst, AddrB: ev.Src, PortA: dport, PortB: sport}, DirBtoA
}

// Endpoint returns the (addr, port) of the given side: DirAtoB → A, else B.
func (k FlowKey) Endpoint(d Dir) (netip.Addr, uint16) {
	if d == DirAtoB {
		return k.AddrA, k.PortA
	}
	return k.AddrB, k.PortB
}
