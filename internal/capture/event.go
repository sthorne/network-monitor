package capture

import (
	"net/netip"
	"time"
)

// Proto identifies the transport protocol of a PacketEvent.
type Proto uint8

const (
	ProtoTCP Proto = iota
	ProtoUDP
	ProtoICMPv4
	ProtoICMPv6
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMPv4:
		return "icmp"
	case ProtoICMPv6:
		return "icmp6"
	}
	return "?"
}

// TCPFlags is a bitmask of the TCP header flags relevant to flow tracking.
type TCPFlags uint8

const (
	FlagFIN TCPFlags = 1 << iota
	FlagSYN
	FlagRST
	FlagPSH
	FlagACK
	FlagURG
)

func (f TCPFlags) Has(m TCPFlags) bool { return f&m == m }

func (f TCPFlags) String() string {
	if f == 0 {
		return "-"
	}
	names := []struct {
		bit  TCPFlags
		name string
	}{
		{FlagSYN, "SYN"}, {FlagFIN, "FIN"}, {FlagRST, "RST"},
		{FlagPSH, "PSH"}, {FlagACK, "ACK"}, {FlagURG, "URG"},
	}
	out := make([]byte, 0, 24)
	for _, n := range names {
		if f&n.bit != 0 {
			if len(out) > 0 {
				out = append(out, ',')
			}
			out = append(out, n.name...)
		}
	}
	return string(out)
}

// MaxSniffPayload bounds how much application payload is copied into an event
// for protocol sniffing.
const MaxSniffPayload = 512

// PacketEvent is the decoded summary of one captured packet. It is the only
// type that crosses from the capture layer into flow tracking, and it owns all
// of its memory (Payload is a copy, never a slice into the capture buffer).
type PacketEvent struct {
	TS      time.Time
	WireLen int
	Proto   Proto

	Src, Dst         netip.Addr
	SrcPort, DstPort uint16

	// TCP only.
	Seq, Ack   uint32
	Flags      TCPFlags
	Window     uint16
	PayloadLen int
	Payload    []byte // first <=MaxSniffPayload bytes of payload, nil if none

	// ICMP only. For echo request/reply, ID carries the echo identifier.
	ICMPType, ICMPCode uint8
	ICMPID             uint16

	// Raw is a copy of the whole captured frame, set only when the decoder
	// runs with KeepRaw (dnsmon uses it for packet export). When KeepRaw is
	// on, Payload also carries the full transport payload instead of the
	// MaxSniffPayload-capped prefix.
	Raw []byte
}
