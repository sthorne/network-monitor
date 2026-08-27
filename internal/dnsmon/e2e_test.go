package dnsmon_test

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

	"github.com/sthorne/network-monitor/internal/capture"
	"github.com/sthorne/network-monitor/internal/dnsmon"
)

var (
	resolver = net.IP{192, 0, 2, 53}
	clientA  = net.IP{10, 1, 0, 11}
	clientB  = net.IP{10, 1, 0, 12}
	authSrv  = net.IP{199, 43, 135, 53}
)

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

func (b *pcapBuilder) close()               { b.f.Close() }
func (b *pcapBuilder) step(d time.Duration) { b.ts = b.ts.Add(d) }

func (b *pcapBuilder) udp(srcIP, dstIP net.IP, srcPort, dstPort layers.UDPPort, payload []byte) {
	b.t.Helper()
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: srcIP, DstIP: dstIP}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	udp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
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

func query(id uint16, name string, qtype uint16) []byte {
	msg := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	return append(msg, question(name, qtype)...)
}

func response(id uint16, name string, qtype uint16, rcode uint8, answers uint16) []byte {
	msg := []byte{byte(id >> 8), byte(id), 0x81, 0x80 | rcode, 0, 1, byte(answers >> 8), byte(answers), 0, 0, 0, 0}
	return append(msg, question(name, qtype)...)
}

func question(name string, qtype uint16) []byte {
	var q []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			q = append(q, byte(i-start))
			q = append(q, name[start:i]...)
			start = i + 1
		}
	}
	q = append(q, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return q
}

// writeStory scripts a recursive resolver's traffic: a recursed lookup, a
// cache hit, an NXDOMAIN, and an upstream query that never gets an answer.
func writeStory(t *testing.T, path string) {
	b := newPcapBuilder(t, path)
	defer b.close()

	// Recursed lookup: client A → resolver → auth → back.
	b.udp(clientA, resolver, 54001, 53, query(0x1111, "www.example.com", 1))
	b.udp(resolver, authSrv, 40001, 53, query(0x2001, "www.example.com", 1))
	b.udp(authSrv, resolver, 53, 40001, response(0x2001, "www.example.com", 1, 0, 1))
	b.udp(resolver, clientA, 53, 54001, response(0x1111, "www.example.com", 1, 0, 1))

	// Cache hit: client B, no upstream traffic.
	b.udp(clientB, resolver, 55002, 53, query(0x1212, "www.example.com", 28))
	b.udp(resolver, clientB, 53, 55002, response(0x1212, "www.example.com", 28, 0, 1))

	// NXDOMAIN.
	b.udp(clientB, resolver, 55003, 53, query(0x3333, "nope.example.com", 1))
	b.udp(resolver, authSrv, 40002, 53, query(0x2002, "nope.example.com", 1))
	b.udp(authSrv, resolver, 53, 40002, response(0x2002, "nope.example.com", 1, 3, 0))
	b.udp(resolver, clientB, 53, 55003, response(0x3333, "nope.example.com", 1, 3, 0))

	// Upstream timeout: the auth never answers.
	b.udp(resolver, authSrv, 40003, 53, query(0x2f2f, "slow.example.net", 2))
	// Trailing packet 10s later so the replay clock passes the query timeout.
	b.step(10 * time.Second)
	b.udp(clientA, resolver, 54009, 53, query(0x0777, "tail.example.com", 1))
	b.udp(resolver, clientA, 53, 54009, response(0x0777, "tail.example.com", 1, 0, 1))
}

func runFile(t *testing.T, path string) dnsmon.Snapshot {
	t.Helper()
	src, err := capture.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan capture.PacketEvent, 4096)
	cfg := dnsmon.DefaultConfig()
	cfg.FileMode = true
	tracker := dnsmon.NewTracker(cfg, events)

	go tracker.Run(ctx)
	dec := capture.NewDecoder(src.LinkType(), capture.Filter{Port: 53})
	if err := capture.Run(ctx, src, dec, events, &capture.Stats{}); err != nil {
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
	return dnsmon.Snapshot{}
}

func findRow(s dnsmon.Snapshot, qid uint16) *dnsmon.Row {
	for i := range s.Rows {
		if s.Rows[i].QID == qid {
			return &s.Rows[i]
		}
	}
	return nil
}

func TestEndToEndPcap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.pcap")
	writeStory(t, path)
	snap := runFile(t, path)

	if len(snap.Rows) != 7 {
		t.Fatalf("transactions = %d, want 7", len(snap.Rows))
	}
	if len(snap.Resolvers) != 1 || snap.Resolvers[0].String() != "192.0.2.53" {
		t.Fatalf("resolvers = %v, want [192.0.2.53]", snap.Resolvers)
	}

	cs, us := snap.Sides[dnsmon.SideClient], snap.Sides[dnsmon.SideUpstream]
	if cs.Queries != 4 || cs.Answered != 4 {
		t.Errorf("client side = %+v, want 4 queries all answered", cs)
	}
	if us.Queries != 3 || us.Answered != 2 || us.Timeout != 1 {
		t.Errorf("upstream side = %+v, want 3 queries, 2 answered, 1 timeout", us)
	}

	// The recursed client lookup.
	if r := findRow(snap, 0x1111); r == nil || r.Side != dnsmon.SideClient ||
		r.Querier.String() != "10.1.0.11" || r.QuerierPort != 54001 ||
		r.QName != "www.example.com" || r.QType != 1 || r.State != dnsmon.TxnAnswered {
		t.Errorf("txn 0x1111 = %+v", findRow(snap, 0x1111))
	}
	// Its upstream leg, classified right even though the resolver uses a
	// high source port.
	if r := findRow(snap, 0x2001); r == nil || r.Side != dnsmon.SideUpstream ||
		r.Server.String() != "199.43.135.53" || r.State != dnsmon.TxnAnswered {
		t.Errorf("txn 0x2001 = %+v", findRow(snap, 0x2001))
	}
	// NXDOMAIN propagates to both sides.
	if r := findRow(snap, 0x3333); r == nil || r.RCode != 3 {
		t.Errorf("txn 0x3333 = %+v, want NXDOMAIN", findRow(snap, 0x3333))
	}
	// The unanswered upstream query timed out via the packet-timestamp clock.
	if r := findRow(snap, 0x2f2f); r == nil || r.State != dnsmon.TxnTimeout {
		t.Errorf("txn 0x2f2f = %+v, want TIMEOUT", findRow(snap, 0x2f2f))
	}
	// The cache hit produced no upstream row.
	if r := findRow(snap, 0x1212); r == nil || r.Side != dnsmon.SideClient || r.QType != 28 {
		t.Errorf("txn 0x1212 = %+v", findRow(snap, 0x1212))
	}
}
