package analyze

import (
	"testing"
	"time"

	"github.com/sthorne/network-monitor/internal/capture"
)

// clock hands out timestamps advancing 1ms per packet.
type clock struct{ t time.Time }

func newClock() *clock { return &clock{t: time.Unix(1000, 0)} }

func (c *clock) next() time.Time {
	c.t = c.t.Add(time.Millisecond)
	return c.t
}

func TestRetransmitDetection(t *testing.T) {
	var tr SeqTracker
	c := newClock()
	tr.Observe(c.next(), 1000, 0, capture.FlagSYN, 65535, 0)
	tr.Observe(c.next(), 1001, 1, capture.FlagACK|capture.FlagPSH, 65535, 100) // 1001..1101
	if _, issues := tr.Observe(c.next(), 1001, 1, capture.FlagACK|capture.FlagPSH, 65535, 100); issues&IssueRetransmissions == 0 {
		t.Fatalf("identical resend not flagged as retransmission")
	}
	if tr.Retransmits != 1 {
		t.Errorf("Retransmits = %d, want 1", tr.Retransmits)
	}
	// New data advances normally.
	if note, _ := tr.Observe(c.next(), 1101, 1, capture.FlagACK, 65535, 100); note&NoteRetransmit != 0 {
		t.Errorf("fresh segment flagged as retransmission")
	}
}

func TestRetransmitAcrossSeqWrap(t *testing.T) {
	var tr SeqTracker
	c := newClock()
	start := uint32(0xFFFFFF00)
	tr.Observe(c.next(), start, 0, capture.FlagSYN, 65535, 0)
	tr.Observe(c.next(), start+1, 0, capture.FlagACK, 65535, 1000) // wraps past 0
	if note, _ := tr.Observe(c.next(), start+1, 0, capture.FlagACK, 65535, 1000); note&NoteRetransmit == 0 {
		t.Fatalf("retransmit across seq wrap not detected")
	}
	// Continuing past the wrap is normal.
	next := start + 1 + 1000
	if note, _ := tr.Observe(c.next(), next, 0, capture.FlagACK, 65535, 500); note&NoteRetransmit != 0 {
		t.Errorf("post-wrap advance flagged as retransmission")
	}
}

func TestDupAckRun(t *testing.T) {
	var tr SeqTracker
	c := newClock()
	tr.Observe(c.next(), 1, 5000, capture.FlagACK, 500, 0)
	var issues IssueSet
	for i := 0; i < 3; i++ {
		_, is := tr.Observe(c.next(), 1, 5000, capture.FlagACK, 500, 0)
		issues |= is
	}
	if issues&IssueDupAcks == 0 {
		t.Fatalf("3 duplicate ACKs not flagged")
	}
	// A different ack resets the run.
	tr.Observe(c.next(), 1, 6000, capture.FlagACK, 500, 0)
	if _, is := tr.Observe(c.next(), 1, 6000, capture.FlagACK, 500, 0); is&IssueDupAcks != 0 {
		t.Errorf("run not reset after new ack")
	}
}

func TestDupAckIgnoresSlowHeartbeats(t *testing.T) {
	// Identical ACKs seconds apart (keepalives/heartbeats) must not count as
	// a duplicate-ACK run — real dup-ACK bursts arrive within milliseconds.
	var tr SeqTracker
	ts := time.Unix(1000, 0)
	var issues IssueSet
	for i := 0; i < 10; i++ {
		ts = ts.Add(2 * time.Second)
		_, is := tr.Observe(ts, 1, 5000, capture.FlagACK, 500, 0)
		issues |= is
	}
	if issues&IssueDupAcks != 0 {
		t.Errorf("slow heartbeat ACKs wrongly flagged as duplicate ACKs")
	}
}

func TestDupAckIgnoresKeepaliveSeq(t *testing.T) {
	// Keepalive probes sit at seq = HighestSeqEnd-1 and must not count.
	var tr SeqTracker
	c := newClock()
	tr.Observe(c.next(), 1000, 0, capture.FlagSYN, 65535, 0)
	tr.Observe(c.next(), 1001, 500, capture.FlagACK, 65535, 100) // HighestSeqEnd = 1101
	var issues IssueSet
	for i := 0; i < 4; i++ {
		_, is := tr.Observe(c.next(), 1100, 500, capture.FlagACK, 65535, 0) // seq = end-1
		issues |= is
	}
	if issues&IssueDupAcks != 0 {
		t.Errorf("keepalive-position ACKs wrongly flagged as duplicate ACKs")
	}
}

func TestOutOfOrderGapFill(t *testing.T) {
	var tr SeqTracker
	c := newClock()
	tr.Observe(c.next(), 1000, 0, capture.FlagSYN, 65535, 0)
	tr.Observe(c.next(), 1001, 1, capture.FlagACK, 65535, 100) // 1001..1101
	tr.Observe(c.next(), 1201, 1, capture.FlagACK, 65535, 100) // gap: 1101..1201 missing
	note, issues := tr.Observe(c.next(), 1101, 1, capture.FlagACK, 65535, 100)
	if note&NoteOutOfOrder == 0 || issues&IssueOutOfOrder == 0 {
		t.Fatalf("gap-filling segment not flagged out-of-order (note=%v issues=%v)", note, issues)
	}
	if tr.Retransmits != 0 {
		t.Errorf("gap fill wrongly counted as retransmission")
	}
}

func TestZeroWindow(t *testing.T) {
	var tr SeqTracker
	c := newClock()
	tr.Observe(c.next(), 1, 100, capture.FlagACK, 0, 0)
	if tr.ZeroWindows != 1 {
		t.Fatalf("zero window not counted")
	}
	// SYN and RST are exempt.
	var tr2 SeqTracker
	tr2.Observe(c.next(), 1, 0, capture.FlagSYN, 0, 0)
	if tr2.ZeroWindows != 0 {
		t.Errorf("SYN with window 0 wrongly counted")
	}
}

func TestIssueSetNames(t *testing.T) {
	s := IssueRetransmissions | IssueConnRefused
	if s.Count() != 2 {
		t.Errorf("Count = %d, want 2", s.Count())
	}
	names := s.Names()
	if len(names) != 2 {
		t.Errorf("Names = %v, want 2 entries", names)
	}
}
