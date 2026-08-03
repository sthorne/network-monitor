// Package analyze contains per-flow diagnostics: TCP sequence-based issue
// detection and application-protocol identification. All detectors keep
// bounded per-direction scalar state — no packet history is stored here.
package analyze

import (
	"strings"
	"time"

	"github.com/sthorne/network-monitor/internal/capture"
)

// IssueSet is a bitmask of problems detected on a flow.
type IssueSet uint16

const (
	IssueRetransmissions IssueSet = 1 << iota
	IssueDupAcks
	IssueOutOfOrder
	IssueZeroWindow
	IssueConnRefused
	IssueHalfOpen
	IssueUnidirectional
	IssueHighRTT
	IssueLongIdle
)

var issueNames = []struct {
	bit  IssueSet
	name string
}{
	{IssueConnRefused, "connection refused"},
	{IssueRetransmissions, "retransmissions"},
	{IssueDupAcks, "duplicate ACKs"},
	{IssueOutOfOrder, "out-of-order segments"},
	{IssueZeroWindow, "zero window"},
	{IssueHalfOpen, "half-open (handshake incomplete)"},
	{IssueUnidirectional, "unidirectional traffic"},
	{IssueHighRTT, "high handshake RTT"},
	{IssueLongIdle, "long idle"},
}

// Names returns human-readable labels for every set bit.
func (s IssueSet) Names() []string {
	var out []string
	for _, n := range issueNames {
		if s&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

func (s IssueSet) String() string { return strings.Join(s.Names(), ", ") }

// Count returns the number of set issue bits.
func (s IssueSet) Count() int {
	n := 0
	for v := s; v != 0; v &= v - 1 {
		n++
	}
	return n
}

// NoteFlag annotates a single packet in a flow's ring buffer with the
// detector that flagged it.
type NoteFlag uint8

const (
	NoteRetransmit NoteFlag = 1 << iota
	NoteDupAck
	NoteOutOfOrder
	NoteZeroWindow
)

func (n NoteFlag) String() string {
	var parts []string
	if n&NoteRetransmit != 0 {
		parts = append(parts, "RETRANS")
	}
	if n&NoteDupAck != 0 {
		parts = append(parts, "DUPACK")
	}
	if n&NoteOutOfOrder != 0 {
		parts = append(parts, "OOO")
	}
	if n&NoteZeroWindow != 0 {
		parts = append(parts, "ZEROWIN")
	}
	return strings.Join(parts, ",")
}

// dupAckWindow bounds how close together ACKs must be to count as a
// duplicate-ACK run. Real dup-ACK bursts react to loss within milliseconds;
// keepalive heartbeats repeating the same ack arrive seconds apart.
const dupAckWindow = 500 * time.Millisecond

// SeqTracker holds one direction's TCP sequence state. All sequence
// comparisons go through signed 32-bit deltas so wraparound is handled.
type SeqTracker struct {
	init          bool
	ISN           uint32
	HighestSeqEnd uint32 // max(seq + segment length) observed
	LastAck       uint32
	LastWindow    uint16
	DupAckRun     int
	lastAckTS     time.Time
	gapPending    bool

	Retransmits uint64
	OutOfOrder  uint64
	ZeroWindows uint64
	DupAcks     uint64
}

// Initialized reports whether an ISN has been recorded for this direction.
func (t *SeqTracker) Initialized() bool { return t.init }

// RelSeq converts an absolute sequence number to ISN-relative.
func (t *SeqTracker) RelSeq(seq uint32) uint32 {
	if !t.init {
		return 0
	}
	return seq - t.ISN
}

func seqBefore(a, b uint32) bool { return int32(a-b) < 0 }
func seqAtMost(a, b uint32) bool { return int32(a-b) <= 0 }

// Observe processes one TCP segment in this direction and returns packet
// notes plus any newly raised flow issues.
func (t *SeqTracker) Observe(ts time.Time, seq, ack uint32, flags capture.TCPFlags, window uint16, payloadLen int) (NoteFlag, IssueSet) {
	var note NoteFlag
	var issues IssueSet

	seqLen := payloadLen
	if flags.Has(capture.FlagSYN) {
		seqLen++
	}
	if flags.Has(capture.FlagFIN) {
		seqLen++
	}
	seqEnd := seq + uint32(seqLen)

	if window == 0 && !flags.Has(capture.FlagRST) && !flags.Has(capture.FlagSYN) {
		t.ZeroWindows++
		note |= NoteZeroWindow
		issues |= IssueZeroWindow
	}

	// Duplicate ACK: pure ACK repeating the previous ack with the same window,
	// sent from the current send position. Keepalive probes look similar but
	// use seq = HighestSeqEnd-1, so the seq check excludes them.
	pureAck := flags.Has(capture.FlagACK) && payloadLen == 0 &&
		flags&(capture.FlagSYN|capture.FlagFIN|capture.FlagRST) == 0
	if pureAck && t.init && ack == t.LastAck && window == t.LastWindow && seq == t.HighestSeqEnd &&
		(t.lastAckTS.IsZero() || ts.Sub(t.lastAckTS) <= dupAckWindow) {
		t.DupAckRun++
		if t.DupAckRun >= 3 {
			t.DupAcks++
			note |= NoteDupAck
			issues |= IssueDupAcks
		}
	} else if flags.Has(capture.FlagACK) {
		t.DupAckRun = 0
		t.LastAck = ack
	}
	if pureAck {
		t.lastAckTS = ts
	}
	if !flags.Has(capture.FlagRST) && !flags.Has(capture.FlagSYN) {
		t.LastWindow = window
	}

	if !t.init {
		t.init = true
		t.ISN = seq
		t.HighestSeqEnd = seqEnd
		return note, issues
	}

	if seqLen > 0 {
		switch {
		case seqAtMost(seqEnd, t.HighestSeqEnd):
			// Entirely below the high-water mark: a gap-filling segment after a
			// jump is counted as out-of-order delivery, otherwise a retransmit.
			if t.gapPending {
				t.OutOfOrder++
				note |= NoteOutOfOrder
				issues |= IssueOutOfOrder
				t.gapPending = false
			} else {
				t.Retransmits++
				note |= NoteRetransmit
				issues |= IssueRetransmissions
			}
		case seqBefore(t.HighestSeqEnd, seq):
			// Jump ahead of the expected sequence: remember the gap.
			t.gapPending = true
			t.HighestSeqEnd = seqEnd
		default:
			t.HighestSeqEnd = seqEnd
		}
	}
	return note, issues
}
