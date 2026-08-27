package dnsui

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/sthorne/network-monitor/internal/capture"
	"github.com/sthorne/network-monitor/internal/dnsmon"
)

// frame serializes a UDP DNS packet for use as a captured frame.
func frame(t *testing.T, src, dst net.IP, sp, dp layers.UDPPort, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: src, DstIP: dst}
	udp := &layers.UDP{SrcPort: sp, DstPort: dp}
	udp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out
}

func TestWriteTxnFilePcapRoundTrip(t *testing.T) {
	t.Chdir(t.TempDir())

	t0 := time.Unix(1700000000, 0)
	qMsg := []byte{0x11, 0x11, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	rMsg := append([]byte{0x11, 0x11, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, qMsg[12:]...)
	qf := frame(t, net.IP{10, 1, 0, 11}, net.IP{192, 0, 2, 53}, 54001, 53, qMsg)
	rf := frame(t, net.IP{192, 0, 2, 53}, net.IP{10, 1, 0, 11}, 53, 54001, rMsg)

	d := dnsmon.TxnDetail{
		Row: dnsmon.Row{
			Seq: 1, QID: 0x1111, QName: "www.example.com", QType: 1,
			Querier: netip.MustParseAddr("10.1.0.11"), QuerierPort: 54001,
			Server: netip.MustParseAddr("192.0.2.53"), ServerPort: 53,
			State:   dnsmon.TxnAnswered,
			QueryTS: t0, RespTS: t0.Add(9 * time.Millisecond),
		},
		QueryMsg: qMsg, RespMsg: rMsg,
		QueryFrame: qf, RespFrame: rf,
		QueryWireLen: len(qf), RespWireLen: len(rf),
	}

	name, err := writeTxnFile(&d, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(name, ".pcap") || !strings.Contains(name, "www.example.com") {
		t.Errorf("filename = %q", name)
	}

	// The written pcap must replay through the capture layer as the same two
	// DNS packets.
	src, err := capture.OpenFile(name)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dec := capture.NewDecoder(src.LinkType(), capture.Filter{})
	dec.KeepRaw = true

	var events []capture.PacketEvent
	for {
		data, ci, err := src.ReadPacketData()
		if err != nil {
			break
		}
		if ev, ok := dec.Decode(data, ci); ok {
			events = append(events, ev)
		}
	}
	if len(events) != 2 {
		t.Fatalf("replayed packets = %d, want 2", len(events))
	}
	if string(events[0].Payload) != string(qMsg) || string(events[1].Payload) != string(rMsg) {
		t.Error("replayed DNS payloads differ from originals")
	}
	if !events[0].TS.Equal(t0) || !events[1].TS.Equal(t0.Add(9*time.Millisecond)) {
		t.Errorf("timestamps = %v / %v, want capture times preserved", events[0].TS, events[1].TS)
	}
	if events[0].SrcPort != 54001 || events[0].DstPort != 53 {
		t.Errorf("query tuple = %d→%d", events[0].SrcPort, events[0].DstPort)
	}
}

func TestWriteTxnFileBinFallback(t *testing.T) {
	t.Chdir(t.TempDir())

	qMsg := []byte{0x22, 0x22, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
	d := dnsmon.TxnDetail{
		Row:      dnsmon.Row{Seq: 2, QID: 0x2222, QName: "a", QueryTS: time.Unix(1700000000, 0)},
		QueryMsg: qMsg,
	}
	name, err := writeTxnFile(&d, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(name, "-query.bin") {
		t.Errorf("fallback name = %q", name)
	}
	got, err := os.ReadFile(name)
	if err != nil || string(got) != string(qMsg) {
		t.Errorf("fallback bytes mismatch (err=%v)", err)
	}
}
