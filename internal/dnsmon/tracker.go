package dnsmon

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"github.com/sthorne/network-monitor/internal/capture"
)

// Config tunes DNS transaction tracking.
type Config struct {
	// Resolvers pins the recursive server identities. Empty enables
	// auto-detection: an address that both receives queries and sends
	// queries is a resolver.
	Resolvers []netip.Addr
	// LocalHints seeds auto-detection with addresses known to be local (the
	// capture interface's own addresses in live mode). Ignored when
	// Resolvers is set.
	LocalHints []netip.Addr
	Port       uint16        // DNS port (default 53)
	Timeout    time.Duration // pending queries older than this become TIMEOUT
	MaxTxns    int           // transaction ring capacity (oldest evicted)
	// FileMode freezes the clock at the last packet timestamp instead of
	// advancing it with wall time (correct ages/timeouts for pcap replay).
	FileMode bool
}

// DefaultConfig returns the standard settings.
func DefaultConfig() Config {
	return Config{
		Port:    53,
		Timeout: 5 * time.Second,
		MaxTxns: 4096,
	}
}

// txnKey identifies one outstanding query: the query-direction 5-tuple plus
// the DNS message ID. The matching response inverts the tuple.
type txnKey struct {
	proto           capture.Proto
	querier, server netip.Addr
	querierPort     uint16
	serverPort      uint16
	qid             uint16
}

type txn struct {
	seq     uint64 // unique per tracker, for Detail lookups from the UI
	key     txnKey
	qname   string
	qtype   uint16
	state   TxnState
	rcode   uint8
	answers uint16
	tc      bool
	retries uint32

	queryTS, respTS time.Time

	// Wire bytes for the inspector and packet export. The msg slices are
	// the transport payload (DNS message, TCP length prefix included); the
	// frame slices are whole captured frames, present only when the decoder
	// runs with KeepRaw.
	queryMsg, respMsg     []byte
	queryFrame, respFrame []byte
	queryWireLen          int
	respWireLen           int
}

// txnRing is a fixed-capacity circular buffer of transactions in
// query-arrival order.
type txnRing struct {
	buf  []*txn
	head int // oldest element
	n    int
}

func newTxnRing(cap int) *txnRing {
	if cap < 1 {
		cap = 1
	}
	return &txnRing{buf: make([]*txn, cap)}
}

// push appends t, returning the evicted oldest transaction when full.
func (r *txnRing) push(t *txn) *txn {
	if r.n < len(r.buf) {
		r.buf[(r.head+r.n)%len(r.buf)] = t
		r.n++
		return nil
	}
	old := r.buf[r.head]
	r.buf[r.head] = t
	r.head = (r.head + 1) % len(r.buf)
	return old
}

// each calls fn for every transaction, oldest first.
func (r *txnRing) each(fn func(*txn)) {
	for i := 0; i < r.n; i++ {
		fn(r.buf[(r.head+i)%len(r.buf)])
	}
}

// filter keeps only transactions where fn returns true, preserving order.
func (r *txnRing) filter(fn func(*txn) bool) {
	kept := make([]*txn, 0, r.n)
	r.each(func(t *txn) {
		if fn(t) {
			kept = append(kept, t)
		}
	})
	for i := range r.buf {
		r.buf[i] = nil
	}
	copy(r.buf, kept)
	r.head, r.n = 0, len(kept)
}

type snapshotReq struct{ reply chan Snapshot }
type clearReq struct{ reply chan struct{} }
type detailReq struct {
	seq   uint64
	reply chan detailReply
}
type detailReply struct {
	detail TxnDetail
	ok     bool
}

// Tracker owns the DNS transaction table. A single goroutine (Run) touches
// all state; the UI communicates via rendezvous channels, so there are no
// locks on the packet hot path.
type Tracker struct {
	cfg  Config
	in   <-chan capture.PacketEvent
	reqs chan any
	done chan struct{}

	ring    *txnRing
	pending map[txnKey]*txn

	// Auto-detection: addresses seen sending and receiving queries. An
	// address in both roles is a resolver. Bounded to keep memory flat under
	// address churn.
	autoDetect bool
	querySrcs  map[netip.Addr]struct{}
	queryDsts  map[netip.Addr]struct{}
	resolvers  map[netip.Addr]struct{}

	now        time.Time
	nextSeq    uint64
	totalMsgs  uint64
	totalBytes uint64
	malformed  uint64
	orphans    uint64
	evicted    uint64
	eof        bool
}

const maxDetectAddrs = 8192

// NewTracker builds a tracker consuming events from in.
func NewTracker(cfg Config, in <-chan capture.PacketEvent) *Tracker {
	if cfg.Port == 0 {
		cfg.Port = 53
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxTxns <= 0 {
		cfg.MaxTxns = 4096
	}
	t := &Tracker{
		cfg:        cfg,
		in:         in,
		reqs:       make(chan any),
		done:       make(chan struct{}),
		ring:       newTxnRing(cfg.MaxTxns),
		pending:    make(map[txnKey]*txn),
		autoDetect: len(cfg.Resolvers) == 0,
		querySrcs:  make(map[netip.Addr]struct{}),
		queryDsts:  make(map[netip.Addr]struct{}),
		resolvers:  make(map[netip.Addr]struct{}),
	}
	for _, a := range cfg.Resolvers {
		t.resolvers[a.Unmap()] = struct{}{}
	}
	if t.autoDetect {
		for _, a := range cfg.LocalHints {
			t.resolvers[a.Unmap()] = struct{}{}
		}
	}
	return t
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

// Detail returns the byte-level view of one transaction by its Row.Seq.
// ok=false when the transaction has been evicted or the tracker stopped.
func (t *Tracker) Detail(seq uint64) (TxnDetail, bool) {
	req := detailReq{seq: seq, reply: make(chan detailReply, 1)}
	select {
	case t.reqs <- req:
	case <-t.done:
		return TxnDetail{}, false
	}
	select {
	case r := <-req.reply:
		return r.detail, r.ok
	case <-t.done:
		return TxnDetail{}, false
	}
}

// ClearCompleted removes answered and timed-out transactions, keeping
// pending ones.
func (t *Tracker) ClearCompleted() {
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
	case clearReq:
		t.ring.filter(func(x *txn) bool { return x.state == TxnPending })
		r.reply <- struct{}{}
	case detailReq:
		var found *txn
		t.ring.each(func(x *txn) {
			if x.seq == r.seq {
				found = x
			}
		})
		if found == nil {
			r.reply <- detailReply{}
			return
		}
		r.reply <- detailReply{detail: found.detail(t.side(found)), ok: true}
	}
}

// detail deep-copies the transaction's byte-level view.
func (x *txn) detail(side Side) TxnDetail {
	return TxnDetail{
		Row:          x.row(side),
		QueryMsg:     append([]byte(nil), x.queryMsg...),
		RespMsg:      append([]byte(nil), x.respMsg...),
		QueryFrame:   append([]byte(nil), x.queryFrame...),
		RespFrame:    append([]byte(nil), x.respFrame...),
		QueryWireLen: x.queryWireLen,
		RespWireLen:  x.respWireLen,
	}
}

// row projects the transaction for the UI.
func (x *txn) row(side Side) Row {
	return Row{
		Seq:     x.seq,
		Side:    side,
		Proto:   x.key.proto,
		Querier: x.key.querier, QuerierPort: x.key.querierPort,
		Server: x.key.server, ServerPort: x.key.serverPort,
		QID: x.key.qid, QName: x.qname, QType: x.qtype,
		State: x.state, RCode: x.rcode, Answers: x.answers,
		TC: x.tc, Retries: x.retries,
		QueryTS: x.queryTS, RespTS: x.respTS,
	}
}

func (t *Tracker) apply(ev *capture.PacketEvent) {
	if ev.TS.After(t.now) {
		t.now = ev.TS
	}
	if ev.Proto != capture.ProtoUDP && ev.Proto != capture.ProtoTCP {
		return
	}
	if ev.SrcPort != t.cfg.Port && ev.DstPort != t.cfg.Port {
		return
	}
	if ev.PayloadLen == 0 {
		return // TCP handshake/ack segments
	}
	msg, ok := Parse(ev.Payload, ev.Proto == capture.ProtoTCP)
	if !ok {
		t.malformed++
		return
	}
	t.totalMsgs++
	t.totalBytes += uint64(ev.WireLen)

	if msg.Response {
		t.applyResponse(ev, &msg)
	} else {
		t.applyQuery(ev, &msg)
	}
}

func (t *Tracker) applyQuery(ev *capture.PacketEvent, msg *Msg) {
	if t.autoDetect {
		t.noteQuerier(ev.Src)
		t.noteQueried(ev.Dst)
	}
	key := txnKey{
		proto: ev.Proto, querier: ev.Src, server: ev.Dst,
		querierPort: ev.SrcPort, serverPort: ev.DstPort, qid: msg.ID,
	}
	if prev, ok := t.pending[key]; ok && prev.qname == msg.QName && prev.qtype == msg.QType {
		prev.retries++ // same question re-sent from the same socket
		return
	}
	t.nextSeq++
	x := &txn{
		seq: t.nextSeq,
		key: key, qname: msg.QName, qtype: msg.QType,
		state: TxnPending, queryTS: ev.TS,
		queryMsg: ev.Payload, queryFrame: ev.Raw, queryWireLen: ev.WireLen,
	}
	if old := t.ring.push(x); old != nil {
		if old.state == TxnPending {
			delete(t.pending, old.key)
		}
		t.evicted++
	}
	t.pending[key] = x
}

func (t *Tracker) applyResponse(ev *capture.PacketEvent, msg *Msg) {
	key := txnKey{
		proto: ev.Proto, querier: ev.Dst, server: ev.Src,
		querierPort: ev.DstPort, serverPort: ev.SrcPort, qid: msg.ID,
	}
	x, ok := t.pending[key]
	if !ok || (msg.QName != "" && x.qname != msg.QName) {
		t.orphans++
		return
	}
	x.state = TxnAnswered
	x.respTS = ev.TS
	x.rcode = msg.RCode
	x.answers = msg.ANCount
	x.tc = msg.TC
	x.respMsg = ev.Payload
	x.respFrame = ev.Raw
	x.respWireLen = ev.WireLen
	delete(t.pending, key)
}

func (t *Tracker) noteQuerier(a netip.Addr) {
	if _, ok := t.querySrcs[a]; !ok && len(t.querySrcs) < maxDetectAddrs {
		t.querySrcs[a] = struct{}{}
	}
	if _, ok := t.queryDsts[a]; ok {
		t.resolvers[a] = struct{}{}
	}
}

func (t *Tracker) noteQueried(a netip.Addr) {
	if _, ok := t.queryDsts[a]; !ok && len(t.queryDsts) < maxDetectAddrs {
		t.queryDsts[a] = struct{}{}
	}
	if _, ok := t.querySrcs[a]; ok {
		t.resolvers[a] = struct{}{}
	}
}

// side classifies a transaction against the current resolver set. Checking
// the querier first makes resolver→resolver forwarding read as upstream.
func (t *Tracker) side(x *txn) Side {
	if _, ok := t.resolvers[x.key.querier]; ok {
		return SideUpstream
	}
	return SideClient
}

// sweep times out pending queries. Classification is not cached anywhere, so
// late resolver detection retroactively re-sides old transactions at the
// next snapshot.
func (t *Tracker) sweep() {
	for key, x := range t.pending {
		if t.now.Sub(x.queryTS) > t.cfg.Timeout {
			x.state = TxnTimeout
			delete(t.pending, key)
		}
	}
}

func (t *Tracker) snapshot() Snapshot {
	s := Snapshot{
		Now:        t.now,
		Rows:       make([]Row, 0, t.ring.n),
		TotalMsgs:  t.totalMsgs,
		TotalBytes: t.totalBytes,
		Malformed:  t.malformed,
		Orphans:    t.orphans,
		Evicted:    t.evicted,
		EOF:        t.eof,
	}
	for i := range s.Sides {
		s.Sides[i].RCodes = make(map[uint8]uint64)
	}
	t.ring.each(func(x *txn) {
		side := t.side(x)
		s.Rows = append(s.Rows, x.row(side))
		st := &s.Sides[side]
		st.Queries++
		st.Retries += uint64(x.retries)
		switch x.state {
		case TxnAnswered:
			st.Answered++
			st.RCodes[x.rcode]++
		case TxnTimeout:
			st.Timeout++
		default:
			st.Pending++
		}
	})
	s.Resolvers = make([]netip.Addr, 0, len(t.resolvers))
	for a := range t.resolvers {
		s.Resolvers = append(s.Resolvers, a)
	}
	sort.Slice(s.Resolvers, func(i, j int) bool { return s.Resolvers[i].Less(s.Resolvers[j]) })
	return s
}
