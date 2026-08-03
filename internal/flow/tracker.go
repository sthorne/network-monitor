package flow

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"github.com/sthorne/network-monitor/internal/analyze"
	"github.com/sthorne/network-monitor/internal/capture"
)

// Config tunes flow tracking and issue thresholds.
type Config struct {
	MaxFlows      int
	MaxHosts      int
	UDPTimeout    time.Duration
	ClosedLinger  time.Duration
	RTTThreshold  time.Duration
	IdleThreshold time.Duration
	HalfOpenAfter time.Duration
	// FileMode freezes the clock at the last packet timestamp instead of
	// advancing it with wall time (correct ages/idle for pcap replay).
	FileMode bool
}

// DefaultConfig returns the standard thresholds.
func DefaultConfig() Config {
	return Config{
		MaxFlows:      10000,
		MaxHosts:      4096,
		UDPTimeout:    60 * time.Second,
		ClosedLinger:  30 * time.Second,
		RTTThreshold:  200 * time.Millisecond,
		IdleThreshold: 60 * time.Second,
		HalfOpenAfter: 5 * time.Second,
	}
}

const sniffGiveUpPackets = 10

type hostStats struct {
	flows          uint64
	packets, bytes uint64
}

type snapshotReq struct{ reply chan Snapshot }
type detailReq struct {
	key   FlowKey
	reply chan detailReply
}
type detailReply struct {
	detail FlowDetail
	ok     bool
}
type clearReq struct{ reply chan struct{} }

// Tracker owns the flow table. A single goroutine (Run) touches all state;
// the UI communicates via rendezvous channels, so there are no locks on the
// packet hot path.
type Tracker struct {
	cfg   Config
	in    <-chan capture.PacketEvent
	reqs  chan any
	done  chan struct{}
	flows map[FlowKey]*Flow
	hosts map[netip.Addr]*hostStats

	now        time.Time
	totalPkts  uint64
	totalBytes uint64
	totalFlows uint64
	eof        bool
}

// NewTracker builds a tracker consuming events from in.
func NewTracker(cfg Config, in <-chan capture.PacketEvent) *Tracker {
	return &Tracker{
		cfg:   cfg,
		in:    in,
		reqs:  make(chan any),
		done:  make(chan struct{}),
		flows: make(map[FlowKey]*Flow),
		hosts: make(map[netip.Addr]*hostStats),
	}
}

// Run processes events until ctx is cancelled. It keeps serving snapshot
// requests after the input channel closes (pcap EOF).
func (t *Tracker) Run(ctx context.Context) {
	defer close(t.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	in := t.in
	for {
		select {
		case ev, ok := <-in:
			if !ok {
				in = nil
				t.eof = true
				t.sweep()
				continue
			}
			t.apply(&ev)
		case req := <-t.reqs:
			t.handle(req)
		case <-ticker.C:
			if !t.cfg.FileMode {
				if wall := time.Now(); wall.After(t.now) {
					t.now = wall
				}
			}
			t.sweep()
		case <-ctx.Done():
			return
		}
	}
}

// Snapshot returns a copy of the current state. ok=false when the tracker
// has stopped.
func (t *Tracker) Snapshot() (Snapshot, bool) {
	req := snapshotReq{reply: make(chan Snapshot, 1)}
	select {
	case t.reqs <- req:
	case <-t.done:
		return Snapshot{}, false
	}
	select {
	case s := <-req.reply:
		return s, true
	case <-t.done:
		return Snapshot{}, false
	}
}

// Detail returns the deep-copied detail view of one flow.
func (t *Tracker) Detail(key FlowKey) (FlowDetail, bool) {
	req := detailReq{key: key, reply: make(chan detailReply, 1)}
	select {
	case t.reqs <- req:
	case <-t.done:
		return FlowDetail{}, false
	}
	select {
	case r := <-req.reply:
		return r.detail, r.ok
	case <-t.done:
		return FlowDetail{}, false
	}
}

// ClearClosed removes terminal flows from the table.
func (t *Tracker) ClearClosed() {
	req := clearReq{reply: make(chan struct{}, 1)}
	select {
	case t.reqs <- req:
	case <-t.done:
		return
	}
	select {
	case <-req.reply:
	case <-t.done:
	}
}

func (t *Tracker) handle(req any) {
	switch r := req.(type) {
	case snapshotReq:
		r.reply <- t.snapshot()
	case detailReq:
		f, ok := t.flows[r.key]
		if !ok {
			r.reply <- detailReply{}
			return
		}
		r.reply <- detailReply{detail: f.detail(), ok: true}
	case clearReq:
		for k, f := range t.flows {
			if f.State.Terminal() {
				delete(t.flows, k)
			}
		}
		r.reply <- struct{}{}
	}
}

func (t *Tracker) snapshot() Snapshot {
	s := Snapshot{
		Now:         t.now,
		Flows:       make([]FlowRow, 0, len(t.flows)),
		TotalBytes:  t.totalBytes,
		TotalPkts:   t.totalPkts,
		ActiveFlows: len(t.flows),
		TotalFlows:  t.totalFlows,
		EOF:         t.eof,
	}
	for _, f := range t.flows {
		s.Flows = append(s.Flows, f.row())
	}
	s.TopHosts = t.topHosts(10)
	return s
}

func (t *Tracker) topHosts(n int) []HostRow {
	rows := make([]HostRow, 0, len(t.hosts))
	for addr, h := range t.hosts {
		rows = append(rows, HostRow{Addr: addr, Flows: h.flows, Packets: h.packets, Bytes: h.bytes})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Bytes != rows[j].Bytes {
			return rows[i].Bytes > rows[j].Bytes
		}
		return rows[i].Packets > rows[j].Packets
	})
	if len(rows) > n {
		rows = rows[:n]
	}
	return rows
}

func (t *Tracker) apply(ev *capture.PacketEvent) {
	if ev.TS.After(t.now) {
		t.now = ev.TS
	}
	t.totalPkts++
	t.totalBytes += uint64(ev.WireLen)

	key, dir := KeyFromEvent(ev)
	f, ok := t.flows[key]
	if !ok {
		if len(t.flows) >= t.cfg.MaxFlows {
			t.evictOverCap(1)
		}
		f = &Flow{Key: key, Initiator: dir, FirstSeen: ev.TS}
		if key.Proto != capture.ProtoTCP {
			f.State = StateActive
		}
		t.flows[key] = f
		t.totalFlows++
		t.creditHostFlow(f)
	}
	f.LastSeen = ev.TS

	ds := &f.Stats[dir]
	if ds.First.IsZero() {
		ds.First = ev.TS
	}
	ds.Last = ev.TS
	ds.Packets++
	ds.Bytes += uint64(ev.WireLen)
	ds.PayloadBytes += uint64(ev.PayloadLen)

	// Credit the initiator host with this packet (both directions).
	initAddr, _ := f.Key.Endpoint(f.Initiator)
	if h := t.hosts[initAddr]; h != nil {
		h.packets++
		h.bytes += uint64(ev.WireLen)
	}

	var note analyze.NoteFlag
	if ev.Proto == capture.ProtoTCP {
		var issues analyze.IssueSet
		note, issues = ds.Seq.Observe(ev.TS, ev.Seq, ev.Ack, ev.Flags, ev.Window, ev.PayloadLen)
		f.Issues |= issues
		f.applyTCPState(dir, ev.Flags, ev.TS)
		if f.HandshakeRTT > 0 && f.HandshakeRTT > t.cfg.RTTThreshold {
			f.Issues |= analyze.IssueHighRTT
		}
	} else if ev.Proto == capture.ProtoICMPv4 || ev.Proto == capture.ProtoICMPv6 {
		f.ICMPType, f.ICMPCode = ev.ICMPType, ev.ICMPCode
	}

	// Reactivate terminal UDP pseudo-flows on new traffic.
	if f.State == StateClosed && key.Proto != capture.ProtoTCP {
		f.State = StateActive
		f.ClosedAt = time.Time{}
	}

	t.sniff(f, ds, ev)

	f.Ring.Push(PacketSummary{
		TS:     ev.TS,
		Dir:    dir,
		Flags:  ev.Flags,
		Len:    uint32(ev.PayloadLen),
		Window: ev.Window,
		Note:   note,
		RelSeq: ds.Seq.RelSeq(ev.Seq),
	})
}

func (t *Tracker) creditHostFlow(f *Flow) {
	addr, _ := f.Key.Endpoint(f.Initiator)
	h := t.hosts[addr]
	if h == nil {
		if len(t.hosts) >= t.cfg.MaxHosts {
			t.evictSmallestHost()
		}
		h = &hostStats{}
		t.hosts[addr] = h
	}
	h.flows++
}

func (t *Tracker) evictSmallestHost() {
	var victim netip.Addr
	var min uint64
	first := true
	for addr, h := range t.hosts {
		if first || h.bytes < min {
			victim, min, first = addr, h.bytes, false
		}
	}
	if victim.IsValid() {
		delete(t.hosts, victim)
	}
}

func (t *Tracker) sniff(f *Flow, ds *DirStats, ev *capture.PacketEvent) {
	if f.appDecided || ev.PayloadLen == 0 || len(ev.Payload) == 0 {
		return
	}
	if len(ds.SniffBuf) < capture.MaxSniffPayload {
		room := capture.MaxSniffPayload - len(ds.SniffBuf)
		chunk := ev.Payload
		if len(chunk) > room {
			chunk = chunk[:room]
		}
		ds.SniffBuf = append(ds.SniffBuf, chunk...)
	}
	f.sniffPkts++
	res, decided := analyze.Sniff(ev.Proto, ev.SrcPort, ev.DstPort, ds.SniffBuf)
	if decided {
		f.App = res
		f.appDecided = true
		f.Stats[0].SniffBuf = nil
		f.Stats[1].SniffBuf = nil
		return
	}
	if f.sniffPkts >= sniffGiveUpPackets {
		f.App = analyze.PortFallback(f.Key.Proto, f.Key.PortA, f.Key.PortB)
		f.appDecided = true
		f.Stats[0].SniffBuf = nil
		f.Stats[1].SniffBuf = nil
	}
}

// sweep runs time-based detectors, closes idle UDP flows, and evicts dead
// flows past their linger.
func (t *Tracker) sweep() {
	var evict []FlowKey
	for key, f := range t.flows {
		age := t.now.Sub(f.FirstSeen)
		idle := t.now.Sub(f.LastSeen)

		switch {
		case f.Key.Proto == capture.ProtoTCP:
			if (f.State == StateSynSent || f.State == StateSynRecv) && age > t.cfg.HalfOpenAfter {
				f.Issues |= analyze.IssueHalfOpen
			}
			if f.State == StateEstab && idle > t.cfg.IdleThreshold {
				f.Issues |= analyze.IssueLongIdle
			}
		default:
			if f.State == StateActive && idle > t.cfg.UDPTimeout {
				// Close at sweep time so the flow lingers visibly before eviction.
				f.setState(StateClosed, t.now)
			}
		}

		total := f.Stats[0].Packets + f.Stats[1].Packets
		if (total >= 10 || age > t.cfg.HalfOpenAfter) && total >= 3 &&
			!f.State.Terminal() &&
			(f.Stats[0].Packets == 0 || f.Stats[1].Packets == 0) {
			f.Issues |= analyze.IssueUnidirectional
		}

		if f.State.Terminal() && !f.ClosedAt.IsZero() && t.now.Sub(f.ClosedAt) > t.cfg.ClosedLinger {
			evict = append(evict, key)
		}
	}
	for _, k := range evict {
		delete(t.flows, k)
	}
	if over := len(t.flows) - t.cfg.MaxFlows; over > 0 {
		t.evictOverCap(over)
	}
}

// evictOverCap removes the n least-recently-active flows.
func (t *Tracker) evictOverCap(n int) {
	type cand struct {
		key  FlowKey
		last time.Time
	}
	cands := make([]cand, 0, len(t.flows))
	for k, f := range t.flows {
		cands = append(cands, cand{k, f.LastSeen})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].last.Before(cands[j].last) })
	for i := 0; i < n && i < len(cands); i++ {
		delete(t.flows, cands[i].key)
	}
}
