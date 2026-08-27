package capture

import (
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Filter is an optional Go-side packet filter applied after decoding.
// A zero Filter matches everything.
type Filter struct {
	Host netip.Addr // match either endpoint; zero value disables
	Port uint16     // match either port; 0 disables
}

func (f Filter) match(ev *PacketEvent) bool {
	if f.Host.IsValid() && ev.Src != f.Host && ev.Dst != f.Host {
		return false
	}
	if f.Port != 0 && ev.SrcPort != f.Port && ev.DstPort != f.Port {
		return false
	}
	return true
}

// Decoder turns raw frames into PacketEvents. Not goroutine-safe: use one
// Decoder per capture pump goroutine.
type Decoder struct {
	// KeepRaw copies the whole frame into each event and lifts the payload
	// cap — for consumers that export packets (dnsmon). Off by default:
	// flow tracking only needs the sniff prefix.
	KeepRaw bool

	parser *gopacket.DecodingLayerParser
	eth    layers.Ethernet
	dot1q  layers.Dot1Q
	ip4    layers.IPv4
	ip6    layers.IPv6
	tcp    layers.TCP
	udp    layers.UDP
	icmp4  layers.ICMPv4
	icmp6  layers.ICMPv6
	pay    gopacket.Payload

	decoded []gopacket.LayerType
	filter  Filter
}

// NewDecoder builds a decoder for frames of the given link type. Ethernet,
// raw-IP, null/loopback, and Linux SLL ("any") link types are supported.
func NewDecoder(link layers.LinkType, filter Filter) *Decoder {
	d := &Decoder{filter: filter}
	var first gopacket.LayerType
	switch link {
	case layers.LinkTypeEthernet:
		first = layers.LayerTypeEthernet
	case layers.LinkTypeRaw, layers.LinkTypeIPv4:
		first = layers.LayerTypeIPv4
	case layers.LinkTypeIPv6:
		first = layers.LayerTypeIPv6
	case layers.LinkTypeNull, layers.LinkTypeLoop:
		first = layers.LayerTypeLoopback
	case layers.LinkTypeLinuxSLL:
		first = layers.LayerTypeLinuxSLL
	default:
		first = layers.LayerTypeEthernet
	}
	var loop layers.Loopback
	var sll layers.LinuxSLL
	d.parser = gopacket.NewDecodingLayerParser(first,
		&d.eth, &d.dot1q, &loop, &sll,
		&d.ip4, &d.ip6, &d.tcp, &d.udp, &d.icmp4, &d.icmp6, &d.pay)
	d.parser.IgnoreUnsupported = true
	return d
}

// Decode parses one frame. Returns (event, true) when the frame is a TCP,
// UDP, or ICMP packet passing the filter; (zero, false) otherwise.
func (d *Decoder) Decode(data []byte, ci gopacket.CaptureInfo) (PacketEvent, bool) {
	d.decoded = d.decoded[:0]
	if err := d.parser.DecodeLayers(data, &d.decoded); err != nil {
		// Truncated or unsupported tails are fine as long as we decoded a
		// transport layer below; DecodeLayers fills d.decoded before erroring.
		_ = err
	}

	ev := PacketEvent{TS: ci.Timestamp, WireLen: ci.Length}
	haveNet, haveTransport := false, false
	for _, lt := range d.decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			ev.Src, _ = netip.AddrFromSlice(d.ip4.SrcIP)
			ev.Dst, _ = netip.AddrFromSlice(d.ip4.DstIP)
			haveNet = true
		case layers.LayerTypeIPv6:
			ev.Src, _ = netip.AddrFromSlice(d.ip6.SrcIP)
			ev.Dst, _ = netip.AddrFromSlice(d.ip6.DstIP)
			haveNet = true
		case layers.LayerTypeTCP:
			ev.Proto = ProtoTCP
			ev.SrcPort = uint16(d.tcp.SrcPort)
			ev.DstPort = uint16(d.tcp.DstPort)
			ev.Seq = d.tcp.Seq
			ev.Ack = d.tcp.Ack
			ev.Window = d.tcp.Window
			ev.Flags = tcpFlags(&d.tcp)
			ev.PayloadLen = len(d.tcp.Payload)
			ev.Payload = d.copyPayload(d.tcp.Payload)
			haveTransport = true
		case layers.LayerTypeUDP:
			ev.Proto = ProtoUDP
			ev.SrcPort = uint16(d.udp.SrcPort)
			ev.DstPort = uint16(d.udp.DstPort)
			ev.PayloadLen = len(d.udp.Payload)
			ev.Payload = d.copyPayload(d.udp.Payload)
			haveTransport = true
		case layers.LayerTypeICMPv4:
			ev.Proto = ProtoICMPv4
			ev.ICMPType = d.icmp4.TypeCode.Type()
			ev.ICMPCode = d.icmp4.TypeCode.Code()
			ev.ICMPID = d.icmp4.Id
			haveTransport = true
		case layers.LayerTypeICMPv6:
			ev.Proto = ProtoICMPv6
			ev.ICMPType = d.icmp6.TypeCode.Type()
			ev.ICMPCode = d.icmp6.TypeCode.Code()
			haveTransport = true
		}
	}
	if !haveNet || !haveTransport {
		return PacketEvent{}, false
	}
	ev.Src = ev.Src.Unmap()
	ev.Dst = ev.Dst.Unmap()
	if !d.filter.match(&ev) {
		return PacketEvent{}, false
	}
	if d.KeepRaw {
		ev.Raw = make([]byte, len(data))
		copy(ev.Raw, data)
	}
	return ev, true
}

func tcpFlags(t *layers.TCP) TCPFlags {
	var f TCPFlags
	if t.FIN {
		f |= FlagFIN
	}
	if t.SYN {
		f |= FlagSYN
	}
	if t.RST {
		f |= FlagRST
	}
	if t.PSH {
		f |= FlagPSH
	}
	if t.ACK {
		f |= FlagACK
	}
	if t.URG {
		f |= FlagURG
	}
	return f
}

func (d *Decoder) copyPayload(p []byte) []byte {
	if len(p) == 0 {
		return nil
	}
	n := len(p)
	if !d.KeepRaw && n > MaxSniffPayload {
		n = MaxSniffPayload
	}
	out := make([]byte, n)
	copy(out, p)
	return out
}
