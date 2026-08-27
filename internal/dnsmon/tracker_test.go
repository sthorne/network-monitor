package dnsmon

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sthorne/network-monitor/internal/capture"
)

var (
	resolverIP = netip.MustParseAddr("192.0.2.53")
	clientIP   = netip.MustParseAddr("10.1.0.11")
	authIP     = netip.MustParseAddr("199.43.135.53")
	t0         = time.Unix(1700000000, 0)
)

func udpEvent(ts time.Time, src, dst netip.Addr, sp, dp uint16, payload []byte) capture.PacketEvent {
	return capture.PacketEvent{
		TS: ts, WireLen: 42 + len(payload), Proto: capture.ProtoUDP,
		Src: src, Dst: dst, SrcPort: sp, DstPort: dp,
		PayloadLen: len(payload), Payload: payload,
	}
}

func respMsg(id uint16, name string, qtype uint16, rcode uint8, answers uint16) []byte {
	b := buildMsg(id, 0x8180|uint16(rcode), name, qtype)
	b[6], b[7] = byte(answers>>8), byte(answers)
	return b
}

func newTestTracker(cfg Config) *Tracker {
	cfg.FileMode = true
	return NewTracker(cfg, nil)
}

func snap(t *Tracker) Snapshot { return t.snapshot() }

func TestClientAndUpstreamClassification(t *testing.T) {
	tr := newTestTracker(DefaultConfig())

	// Client asks the resolver; resolver recurses to the auth; both answered.
	q := buildMsg(0x1111, 0x0100, "www.example.com", 1)
	uq := buildMsg(0x2222, 0x0100, "www.example.com", 1)
	ev := udpEvent(t0, clientIP, resolverIP, 54001, 53, q)
	tr.apply(&ev)
	ev = udpEvent(t0.Add(1*time.Millisecond), resolverIP, authIP, 40001, 53, uq)
	tr.apply(&ev)
	ev = udpEvent(t0.Add(9*time.Millisecond), authIP, resolverIP, 53, 40001, respMsg(0x2222, "www.example.com", 1, 0, 1))
	tr.apply(&ev)
	ev = udpEvent(t0.Add(10*time.Millisecond), resolverIP, clientIP, 53, 54001, respMsg(0x1111, "www.example.com", 1, 0, 1))
	tr.apply(&ev)

	s := snap(tr)
	if len(s.Rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(s.Rows))
	}
	// Auto-detection: the resolver both received (from client) and sent (to
	// auth) queries, so it must be identified.
	if len(s.Resolvers) != 1 || s.Resolvers[0] != resolverIP {
		t.Fatalf("resolvers = %v, want [%v]", s.Resolvers, resolverIP)
	}

	cli := s.Rows[0]
	if cli.Side != SideClient || cli.Querier != clientIP || cli.QuerierPort != 54001 {
		t.Errorf("client row = %+v", cli)
	}
	if cli.QID != 0x1111 || cli.QName != "www.example.com" || cli.QType != 1 {
		t.Errorf("client row qid/qname/qtype = %x/%q/%d", cli.QID, cli.QName, cli.QType)
	}
	if cli.State != TxnAnswered || cli.RCode != 0 || cli.Latency() != 10*time.Millisecond {
		t.Errorf("client row outcome = %v rcode=%d lat=%v", cli.State, cli.RCode, cli.Latency())
	}

	up := s.Rows[1]
	if up.Side != SideUpstream || up.Querier != resolverIP || up.Server != authIP {
		t.Errorf("upstream row = %+v", up)
	}
	if up.QID != 0x2222 || up.Latency() != 8*time.Millisecond {
		t.Errorf("upstream qid/lat = %x/%v", up.QID, up.Latency())
	}

	if s.Sides[SideClient].Queries != 1 || s.Sides[SideUpstream].Queries != 1 {
		t.Errorf("side stats = %+v", s.Sides)
	}
	if s.Sides[SideUpstream].RCodes[0] != 1 {
		t.Errorf("upstream rcodes = %v", s.Sides[SideUpstream].RCodes)
	}
}

func TestExplicitResolverConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Resolvers = []netip.Addr{resolverIP}
	tr := newTestTracker(cfg)

	// Only an upstream query is seen (e.g. capture on the outside interface):
	// auto-detection could never classify it, the pinned identity must.
	ev := udpEvent(t0, resolverIP, authIP, 40001, 53, buildMsg(7, 0x0100, "example.net", 2))
	tr.apply(&ev)
	s := snap(tr)
	if len(s.Rows) != 1 || s.Rows[0].Side != SideUpstream {
		t.Fatalf("rows = %+v, want one upstream row", s.Rows)
	}
	if s.Rows[0].State != TxnPending {
		t.Errorf("state = %v, want pending", s.Rows[0].State)
	}
}

func TestTimeoutAndRetry(t *testing.T) {
	tr := newTestTracker(DefaultConfig())

	q := buildMsg(0x5555, 0x0100, "slow.example.net", 2)
	ev := udpEvent(t0, clientIP, resolverIP, 54003, 53, q)
	tr.apply(&ev)
	// Same socket, same QID, same question again: a retry, not a new txn.
	ev = udpEvent(t0.Add(2*time.Second), clientIP, resolverIP, 54003, 53, q)
	tr.apply(&ev)

	s := snap(tr)
	if len(s.Rows) != 1 || s.Rows[0].Retries != 1 {
		t.Fatalf("rows = %+v, want one txn with 1 retry", s.Rows)
	}

	// Advance past the timeout and sweep.
	ev = udpEvent(t0.Add(10*time.Second), clientIP, resolverIP, 54009, 53, buildMsg(9, 0x0100, "other.example.net", 1))
	tr.apply(&ev)
	tr.sweep()

	s = snap(tr)
	var timedOut *Row
	for i := range s.Rows {
		if s.Rows[i].QID == 0x5555 {
			timedOut = &s.Rows[i]
		}
	}
	if timedOut == nil || timedOut.State != TxnTimeout {
		t.Fatalf("txn 0x5555 = %+v, want TIMEOUT", timedOut)
	}
	// A response arriving after the timeout is an orphan, not a match.
	ev = udpEvent(t0.Add(11*time.Second), resolverIP, clientIP, 53, 54003, respMsg(0x5555, "slow.example.net", 2, 0, 1))
	tr.apply(&ev)
	if s := snap(tr); s.Orphans != 1 {
		t.Errorf("orphans = %d, want 1", s.Orphans)
	}
}

func TestOrphanAndQNameMismatch(t *testing.T) {
	tr := newTestTracker(DefaultConfig())

	ev := udpEvent(t0, clientIP, resolverIP, 54001, 53, buildMsg(0x0101, 0x0100, "a.example.com", 1))
	tr.apply(&ev)
	// Response with the right key but a different question: spoof-shaped.
	ev = udpEvent(t0.Add(time.Millisecond), resolverIP, clientIP, 53, 54001, respMsg(0x0101, "b.example.com", 1, 0, 1))
	tr.apply(&ev)

	s := snap(tr)
	if s.Orphans != 1 {
		t.Errorf("orphans = %d, want 1 (qname mismatch must not match)", s.Orphans)
	}
	if s.Rows[0].State != TxnPending {
		t.Errorf("state = %v, want still pending", s.Rows[0].State)
	}
}

func TestRingEviction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxTxns = 3
	tr := newTestTracker(cfg)

	for i := 0; i < 5; i++ {
		ev := udpEvent(t0.Add(time.Duration(i)*time.Millisecond),
			clientIP, resolverIP, uint16(54000+i), 53, buildMsg(uint16(i), 0x0100, "x.example.com", 1))
		tr.apply(&ev)
	}
	s := snap(tr)
	if len(s.Rows) != 3 || s.Evicted != 2 {
		t.Fatalf("rows=%d evicted=%d, want 3/2", len(s.Rows), s.Evicted)
	}
	if s.Rows[0].QID != 2 || s.Rows[2].QID != 4 {
		t.Errorf("ring order = %d..%d, want 2..4", s.Rows[0].QID, s.Rows[2].QID)
	}
	// Evicted pending txns must have left the pending map too.
	if len(tr.pending) != 3 {
		t.Errorf("pending = %d, want 3", len(tr.pending))
	}
}

func TestClearCompleted(t *testing.T) {
	tr := newTestTracker(DefaultConfig())

	ev := udpEvent(t0, clientIP, resolverIP, 54001, 53, buildMsg(1, 0x0100, "done.example.com", 1))
	tr.apply(&ev)
	ev = udpEvent(t0.Add(time.Millisecond), resolverIP, clientIP, 53, 54001, respMsg(1, "done.example.com", 1, 0, 1))
	tr.apply(&ev)
	ev = udpEvent(t0.Add(2*time.Millisecond), clientIP, resolverIP, 54002, 53, buildMsg(2, 0x0100, "wip.example.com", 1))
	tr.apply(&ev)

	tr.ring.filter(func(x *txn) bool { return x.state == TxnPending })
	s := snap(tr)
	if len(s.Rows) != 1 || s.Rows[0].QID != 2 {
		t.Fatalf("after clear rows = %+v, want only pending txn", s.Rows)
	}
}

func TestNonDNSIgnored(t *testing.T) {
	tr := newTestTracker(DefaultConfig())

	// Wrong port entirely.
	ev := udpEvent(t0, clientIP, resolverIP, 5000, 5001, buildMsg(1, 0x0100, "x.example.com", 1))
	tr.apply(&ev)
	// Right port, garbage payload.
	ev = udpEvent(t0, clientIP, resolverIP, 54001, 53, []byte{1, 2, 3})
	tr.apply(&ev)

	s := snap(tr)
	if len(s.Rows) != 0 || s.TotalMsgs != 0 {
		t.Errorf("rows=%d msgs=%d, want 0/0", len(s.Rows), s.TotalMsgs)
	}
	if s.Malformed != 1 {
		t.Errorf("malformed = %d, want 1", s.Malformed)
	}
}

func TestTCPTransactions(t *testing.T) {
	tr := newTestTracker(DefaultConfig())

	inner := buildMsg(0x0909, 0x0100, "big.example.com", 252)
	q := append([]byte{byte(len(inner) >> 8), byte(len(inner))}, inner...)
	ev := capture.PacketEvent{
		TS: t0, WireLen: 60 + len(q), Proto: capture.ProtoTCP,
		Src: clientIP, Dst: resolverIP, SrcPort: 41000, DstPort: 53,
		PayloadLen: len(q), Payload: q,
	}
	tr.apply(&ev)
	rinner := respMsg(0x0909, "big.example.com", 252, 0, 4)
	r := append([]byte{byte(len(rinner) >> 8), byte(len(rinner))}, rinner...)
	ev = capture.PacketEvent{
		TS: t0.Add(3 * time.Millisecond), WireLen: 60 + len(r), Proto: capture.ProtoTCP,
		Src: resolverIP, Dst: clientIP, SrcPort: 53, DstPort: 41000,
		PayloadLen: len(r), Payload: r,
	}
	tr.apply(&ev)

	s := snap(tr)
	if len(s.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(s.Rows))
	}
	r0 := s.Rows[0]
	if r0.Proto != capture.ProtoTCP || r0.State != TxnAnswered || r0.Answers != 4 {
		t.Errorf("tcp txn = %+v", r0)
	}
}
