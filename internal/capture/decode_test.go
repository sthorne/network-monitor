package capture

import (
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	macA = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	macB = net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
)

func serialize(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func ci(data []byte) gopacket.CaptureInfo {
	return gopacket.CaptureInfo{
		Timestamp:     time.Unix(1700000000, 0),
		CaptureLength: len(data),
		Length:        len(data),
	}
}

func TestDecodeTCPv4(t *testing.T) {
	eth := &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{10, 0, 0, 5}, DstIP: net.IP{10, 0, 0, 9}}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 8080, Seq: 12345, Ack: 999,
		SYN: false, ACK: true, PSH: true, Window: 512}
	tcp.SetNetworkLayerForChecksum(ip)
	payload := gopacket.Payload([]byte("GET / HTTP/1.1\r\n"))
	data := serialize(t, eth, ip, tcp, payload)

	dec := NewDecoder(layers.LinkTypeEthernet, Filter{})
	ev, ok := dec.Decode(data, ci(data))
	if !ok {
		t.Fatal("decode failed")
	}
	if ev.Proto != ProtoTCP || ev.Src.String() != "10.0.0.5" || ev.Dst.String() != "10.0.0.9" {
		t.Errorf("bad addrs/proto: %+v", ev)
	}
	if ev.SrcPort != 40000 || ev.DstPort != 8080 || ev.Seq != 12345 || ev.Window != 512 {
		t.Errorf("bad tcp fields: %+v", ev)
	}
	if !ev.Flags.Has(FlagACK) || !ev.Flags.Has(FlagPSH) || ev.Flags.Has(FlagSYN) {
		t.Errorf("bad flags: %v", ev.Flags)
	}
	if ev.PayloadLen != 16 || string(ev.Payload) != "GET / HTTP/1.1\r\n" {
		t.Errorf("bad payload: len=%d %q", ev.PayloadLen, ev.Payload)
	}
}

func TestDecodeVLANUDPv6(t *testing.T) {
	eth := &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeDot1Q}
	dot1q := &layers.Dot1Q{VLANIdentifier: 42, Type: layers.EthernetTypeIPv6}
	ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP,
		SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
	udp := &layers.UDP{SrcPort: 5353, DstPort: 53}
	udp.SetNetworkLayerForChecksum(ip)
	data := serialize(t, eth, dot1q, ip, udp, gopacket.Payload([]byte{0x12, 0x34}))

	dec := NewDecoder(layers.LinkTypeEthernet, Filter{})
	ev, ok := dec.Decode(data, ci(data))
	if !ok {
		t.Fatal("decode failed")
	}
	if ev.Proto != ProtoUDP || ev.Src.String() != "2001:db8::1" || ev.DstPort != 53 {
		t.Errorf("bad vlan/ipv6/udp decode: %+v", ev)
	}
}

func TestDecodeFilter(t *testing.T) {
	eth := &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{10, 0, 0, 5}, DstIP: net.IP{10, 0, 0, 9}}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 8080, ACK: true}
	tcp.SetNetworkLayerForChecksum(ip)
	data := serialize(t, eth, ip, tcp)

	dec := NewDecoder(layers.LinkTypeEthernet, Filter{Port: 443})
	if _, ok := dec.Decode(data, ci(data)); ok {
		t.Error("filter should have dropped port-8080 packet")
	}
	dec = NewDecoder(layers.LinkTypeEthernet, Filter{Port: 8080})
	if _, ok := dec.Decode(data, ci(data)); !ok {
		t.Error("filter should have kept port-8080 packet")
	}
}

func TestDecodeARPIgnored(t *testing.T) {
	eth := &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeARP}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: 1,
		SourceHwAddress: macA, SourceProtAddress: []byte{10, 0, 0, 5},
		DstHwAddress: make([]byte, 6), DstProtAddress: []byte{10, 0, 0, 9},
	}
	data := serialize(t, eth, arp)
	dec := NewDecoder(layers.LinkTypeEthernet, Filter{})
	if _, ok := dec.Decode(data, ci(data)); ok {
		t.Error("ARP should not produce an event")
	}
}
