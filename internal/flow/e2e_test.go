package flow_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/sthorne/network-monitor/internal/analyze"
	"github.com/sthorne/network-monitor/internal/capture"
	"github.com/sthorne/network-monitor/internal/flow"
)

// pcapBuilder writes a scripted packet story to a pcap file.
type pcapBuilder struct {
	t  *testing.T
	w  *pcapgo.Writer
	f  *os.File
	ts time.Time
}

func newPcapBuilder(t *testing.T, path string) *pcapBuilder {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	return &pcapBuilder{t: t, w: w, f: f, ts: time.Unix(1700000000, 0)}
}

func (b *pcapBuilder) close() { b.f.Close() }

func (b *pcapBuilder) step(d time.Duration) { b.ts = b.ts.Add(d) }

func (b *pcapBuilder) write(ls ...gopacket.SerializableLayer) {
	b.t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		b.t.Fatal(err)
	}
	data := buf.Bytes()
	err := b.w.WritePacket(gopacket.CaptureInfo{
		Timestamp: b.ts, CaptureLength: len(data), Length: len(data),
	}, data)
	if err != nil {
		b.t.Fatal(err)
	}
	b.step(2 * time.Millisecond)
}

type tcpSpec struct {
	srcIP, dstIP             net.IP
	srcPort, dstPort         layers.TCPPort
	seq, ack                 uint32
	syn, ackF, fin, rst, psh bool
	window                   uint16
	payload                  []byte
}

func (b *pcapBuilder) tcp(s tcpSpec) {
	b.t.Helper()
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: s.srcIP, DstIP: s.dstIP}
	win := s.window
	if win == 0 && !s.rst {
		win = 65535
	}
	tcp := &layers.TCP{
		SrcPort: s.srcPort, DstPort: s.dstPort, Seq: s.seq, Ack: s.ack,
		SYN: s.syn, ACK: s.ackF, FIN: s.fin, RST: s.rst, PSH: s.psh, Window: win,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	if len(s.payload) > 0 {
		b.write(eth, ip, tcp, gopacket.Payload(s.payload))
	} else {
		b.write(eth, ip, tcp)
	}
}

func (b *pcapBuilder) udp(srcIP, dstIP net.IP, srcPort, dstPort layers.UDPPort, payload []byte) {
	b.t.Helper()
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: srcIP, DstIP: dstIP}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	udp.SetNetworkLayerForChecksum(ip)
	b.write(eth, ip, udp, gopacket.Payload(payload))
}

var (
	client = net.IP{10, 0, 0, 5}
	server = net.IP{10, 0, 0, 9}
	dnsSrv = net.IP{8, 8, 8, 8}
)

// writeStory produces: an HTTP session with one retransmission and a clean
// close; a refused connection (SYN→RST); and a DNS query/response.
func writeStory(t *testing.T, path string) {
	b := newPcapBuilder(t, path)
	defer b.close()

	// --- Flow 1: HTTP with retransmission, clean close.
	req := []byte("GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	b.tcp(tcpSpec{srcIP: client, dstIP: server, srcPort: 40000, dstPort: 80, seq: 1000, syn: true})
	b.tcp(tcpSpec{srcIP: server, dstIP: client, srcPort: 80, dstPort: 40000, seq: 5000, ack: 1001, syn: true, ackF: true})
	b.tcp(tcpSpec{srcIP: client, dstIP: server, srcPort: 40000, dstPort: 80, seq: 1001, ack: 5001, ackF: true})
	b.tcp(tcpSpec{srcIP: client, dstIP: server, srcPort: 40000, dstPort: 80, seq: 1001, ack: 5001, ackF: true, psh: true, payload: req})
	// Retransmit of the request (same seq, same payload).
	b.tcp(tcpSpec{srcIP: client, dstIP: server, srcPort: 40000, dstPort: 80, seq: 1001, ack: 5001, ackF: true, psh: true, payload: req})
	b.tcp(tcpSpec{srcIP: server, dstIP: client, srcPort: 80, dstPort: 40000, seq: 5001, ack: 1001 + uint32(len(req)), ackF: true, psh: true, payload: resp})
	b.tcp(tcpSpec{srcIP: client, dstIP: server, srcPort: 40000, dstPort: 80, seq: 1001 + uint32(len(req)), ack: 5001 + uint32(len(resp)), ackF: true, fin: true})
	b.tcp(tcpSpec{srcIP: server, dstIP: client, srcPort: 80, dstPort: 40000, seq: 5001 + uint32(len(resp)), ack: 1002 + uint32(len(req)), ackF: true, fin: true})
	b.tcp(tcpSpec{srcIP: client, dstIP: server, srcPort: 40000, dstPort: 80, seq: 1002 + uint32(len(req)), ack: 5002 + uint32(len(resp)), ackF: true})

	// --- Flow 2: connection refused.
	b.tcp(tcpSpec{srcIP: client, dstIP: server, srcPort: 40001, dstPort: 9999, seq: 7000, syn: true})
	b.tcp(tcpSpec{srcIP: server, dstIP: client, srcPort: 9999, dstPort: 40001, seq: 0, ack: 7001, rst: true, ackF: true})

	// --- Flow 3: DNS query/response.
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"example", "test"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	b.udp(client, dnsSrv, 53555, 53, q)
	r := append([]byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, q[12:]...)
	b.udp(dnsSrv, client, 53, 53555, r)
}

func runFile(t *testing.T, path string) flow.Snapshot {
	t.Helper()
	src, err := capture.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan capture.PacketEvent, 4096)
	stats := &capture.Stats{}
	dec := capture.NewDecoder(src.LinkType(), capture.Filter{})
	cfg := flow.DefaultConfig()
	cfg.FileMode = true
	tracker := flow.NewTracker(cfg, events)

	go tracker.Run(ctx)
	if err := capture.Run(ctx, src, dec, events, stats); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s, ok := tracker.Snapshot()
		if !ok {
			t.Fatal("tracker stopped")
		}
		if s.EOF {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for EOF snapshot")
	return flow.Snapshot{}
}

func findFlow(s flow.Snapshot, serverPort uint16) *flow.FlowRow {
	for i := range s.Flows {
		if s.Flows[i].ServerPort == serverPort {
			return &s.Flows[i]
		}
	}
	return nil
}

func TestEndToEndPcap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "story.pcap")
	writeStory(t, path)
	snap := runFile(t, path)

	if snap.ActiveFlows != 3 {
		t.Fatalf("flows = %d, want 3", snap.ActiveFlows)
	}

	http := findFlow(snap, 80)
	if http == nil {
		t.Fatal("HTTP flow not found")
	}
	if http.State != flow.StateClosed {
		t.Errorf("HTTP flow state = %v, want CLOSED", http.State)
	}
	if http.App.Name != "HTTP" {
		t.Errorf("HTTP flow app = %q, want HTTP", http.App.Name)
	}
	if http.Issues&analyze.IssueRetransmissions == 0 {
		t.Errorf("HTTP flow missing retransmission issue (issues=%v)", http.Issues)
	}
	if http.ClientAddr.String() != "10.0.0.5" || http.ClientPort != 40000 {
		t.Errorf("HTTP client = %s:%d, want 10.0.0.5:40000", http.ClientAddr, http.ClientPort)
	}

	refused := findFlow(snap, 9999)
	if refused == nil {
		t.Fatal("refused flow not found")
	}
	if refused.State != flow.StateReset {
		t.Errorf("refused flow state = %v, want RST", refused.State)
	}
	if refused.Issues&analyze.IssueConnRefused == 0 {
		t.Errorf("refused flow missing conn-refused issue (issues=%v)", refused.Issues)
	}

	dns := findFlow(snap, 53)
	if dns == nil {
		t.Fatal("DNS flow not found")
	}
	if dns.App.Name != "DNS" || dns.App.Detail != "example.test" {
		t.Errorf("DNS app = %+v, want DNS example.test", dns.App)
	}
	if dns.State != flow.StateActive {
		t.Errorf("DNS flow state = %v, want ACTIVE", dns.State)
	}

	// Top talkers: 10.0.0.5 initiated everything, so it owns all traffic.
	if len(snap.TopHosts) == 0 || snap.TopHosts[0].Addr.String() != "10.0.0.5" {
		t.Fatalf("top host = %+v, want 10.0.0.5 first", snap.TopHosts)
	}
	if snap.TopHosts[0].Flows != 3 {
		t.Errorf("top host flows = %d, want 3", snap.TopHosts[0].Flows)
	}
	if snap.TopHosts[0].Packets != snap.TotalPkts {
		t.Errorf("top host packets = %d, want all %d", snap.TopHosts[0].Packets, snap.TotalPkts)
	}

	// Detail view of the HTTP flow.
	// (Re-run through a fresh tracker to exercise Detail while running.)
	src, err := capture.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan capture.PacketEvent, 4096)
	cfg := flow.DefaultConfig()
	cfg.FileMode = true
	tracker := flow.NewTracker(cfg, events)
	go tracker.Run(ctx)
	if err := capture.Run(ctx, src, capture.NewDecoder(src.LinkType(), capture.Filter{}), events, &capture.Stats{}); err != nil {
		t.Fatal(err)
	}
	for {
		if s, ok := tracker.Snapshot(); ok && s.EOF {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	d, ok := tracker.Detail(http.Key)
	if !ok {
		t.Fatal("Detail lookup failed")
	}
	if d.HandshakeRTT <= 0 {
		t.Errorf("handshake RTT = %v, want > 0", d.HandshakeRTT)
	}
	if d.Out.Retransmits != 1 {
		t.Errorf("client retransmits = %d, want 1", d.Out.Retransmits)
	}
	if len(d.Packets) != 9 {
		t.Errorf("ring packets = %d, want 9", len(d.Packets))
	}
	retransSeen := false
	for _, p := range d.Packets {
		if p.Note&analyze.NoteRetransmit != 0 {
			retransSeen = true
		}
	}
	if !retransSeen {
		t.Errorf("no packet in ring annotated RETRANS")
	}
}

func TestUDPIdleTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "udp.pcap")
	b := newPcapBuilder(t, path)
	b.udp(client, dnsSrv, 50000, 53, []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0})
	// Second flow two minutes later: the first should have idled out to CLOSED.
	b.step(2 * time.Minute)
	b.udp(client, dnsSrv, 50001, 53, []byte{0x12, 0x35, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0})
	b.close()

	snap := runFile(t, path)
	var closed, active int
	for _, r := range snap.Flows {
		switch r.State {
		case flow.StateClosed:
			closed++
		case flow.StateActive:
			active++
		}
	}
	if closed != 1 || active != 1 {
		t.Errorf("closed=%d active=%d, want 1/1 (packet-timestamp clock should idle out the first flow)", closed, active)
	}
}
