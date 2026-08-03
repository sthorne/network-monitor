package flow

import (
	"time"

	"github.com/sthorne/network-monitor/internal/analyze"
	"github.com/sthorne/network-monitor/internal/capture"
)

// TCPState is the observed session state. UDP and ICMP pseudo-flows only use
// StateActive/StateClosed.
type TCPState uint8

const (
	StateUnknown TCPState = iota
	StateSynSent
	StateSynRecv
	StateEstab
	StateFinWait
	StateClosing
	StateClosed
	StateReset
	StateActive
)

func (s TCPState) String() string {
	switch s {
	case StateSynSent:
		return "SYN_SENT"
	case StateSynRecv:
		return "SYN_RECV"
	case StateEstab:
		return "ESTAB"
	case StateFinWait:
		return "FIN_WAIT"
	case StateClosing:
		return "CLOSING"
	case StateClosed:
		return "CLOSED"
	case StateReset:
		return "RST"
	case StateActive:
		return "ACTIVE"
	}
	return "?"
}

// Terminal reports whether the flow has ended.
func (s TCPState) Terminal() bool { return s == StateClosed || s == StateReset }

// RingSize is the per-flow packet-summary history kept for the detail view.
const RingSize = 200

// PacketSummary is a compact record of one packet for the detail timeline.
type PacketSummary struct {
	TS     time.Time
	Dir    Dir
	Flags  capture.TCPFlags
	Len    uint32 // payload length
	Window uint16
	Note   analyze.NoteFlag
	RelSeq uint32
}

// PacketRing is a fixed-size overwrite-oldest buffer of packet summaries.
type PacketRing struct {
	buf  [RingSize]PacketSummary
	head int // next write position
	n    int
}

func (r *PacketRing) Push(s PacketSummary) {
	r.buf[r.head] = s
	r.head = (r.head + 1) % RingSize
	if r.n < RingSize {
		r.n++
	}
}

// All returns the ring contents oldest→newest as a fresh slice.
func (r *PacketRing) All() []PacketSummary {
	out := make([]PacketSummary, 0, r.n)
	start := (r.head - r.n + RingSize) % RingSize
	for i := 0; i < r.n; i++ {
		out = append(out, r.buf[(start+i)%RingSize])
	}
	return out
}

// Len returns the number of summaries stored.
func (r *PacketRing) Len() int { return r.n }

// DirStats accumulates one direction of a flow.
type DirStats struct {
	Packets, Bytes, PayloadBytes uint64
	First, Last                  time.Time
	Seq                          analyze.SeqTracker
	SniffBuf                     []byte
}

// Flow is the tracked state of one conversation. Owned exclusively by the
// Tracker goroutine; the UI only ever sees copies.
type Flow struct {
	Key       FlowKey
	Initiator Dir // side that sent the first packet (first SYN for TCP)
	State     TCPState
	Midstream bool // picked up without seeing the handshake

	Stats  [2]DirStats // indexed by Dir
	Issues analyze.IssueSet

	App        analyze.Result
	appDecided bool
	sniffPkts  int

	SynTime, SynAckTime time.Time
	HandshakeRTT        time.Duration

	FirstSeen, LastSeen time.Time
	ClosedAt            time.Time

	finSeen [2]bool
	Ring    PacketRing

	// ICMP detail (last observed type/code).
	ICMPType, ICMPCode uint8
}

// InitiatorStats and ResponderStats return the per-direction stats relative
// to who started the conversation.
func (f *Flow) InitiatorStats() *DirStats { return &f.Stats[f.Initiator] }
func (f *Flow) ResponderStats() *DirStats { return &f.Stats[f.Initiator.Reverse()] }

// Duration is the observed lifetime of the flow.
func (f *Flow) Duration() time.Duration {
	if f.LastSeen.Before(f.FirstSeen) {
		return 0
	}
	return f.LastSeen.Sub(f.FirstSeen)
}
