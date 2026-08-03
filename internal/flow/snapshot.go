package flow

import (
	"net/netip"
	"time"

	"github.com/sthorne/network-monitor/internal/analyze"
	"github.com/sthorne/network-monitor/internal/capture"
)

// FlowRow is a value-type projection of one flow for the UI. It shares no
// memory with live tracker state.
type FlowRow struct {
	Key       FlowKey
	Proto     capture.Proto
	State     TCPState
	Midstream bool
	App       analyze.Result
	Issues    analyze.IssueSet

	ClientAddr netip.Addr
	ClientPort uint16
	ServerAddr netip.Addr
	ServerPort uint16

	FirstSeen, LastSeen time.Time
	// Out = initiator→responder, In = responder→initiator.
	PktsOut, PktsIn   uint64
	BytesOut, BytesIn uint64
}

// DirView is one direction's detailed counters for the detail screen.
type DirView struct {
	Packets, Bytes, PayloadBytes                  uint64
	Retransmits, DupAcks, OutOfOrder, ZeroWindows uint64
}

// FlowDetail is the deep-copied detail-view projection of one flow.
type FlowDetail struct {
	Row          FlowRow
	HandshakeRTT time.Duration
	Midstream    bool
	ICMPLabel    string
	Out, In      DirView // relative to initiator
	Initiator    Dir
	Packets      []PacketSummary
}

// HostRow is one client's running totals for the top-talkers view.
type HostRow struct {
	Addr           netip.Addr
	Flows          uint64
	Packets, Bytes uint64
}

// Snapshot is the tracker state copy handed to the UI on each tick.
type Snapshot struct {
	Now         time.Time
	Flows       []FlowRow
	TopHosts    []HostRow
	TotalBytes  uint64
	TotalPkts   uint64
	ActiveFlows int
	TotalFlows  uint64 // includes evicted
	EOF         bool
}

func (f *Flow) row() FlowRow {
	ca, cp := f.Key.Endpoint(f.Initiator)
	sa, sp := f.Key.Endpoint(f.Initiator.Reverse())
	app := f.App
	if !f.appDecided && app.Name == "" {
		app = analyze.PortFallback(f.Key.Proto, f.Key.PortA, f.Key.PortB)
	}
	return FlowRow{
		Key:        f.Key,
		Proto:      f.Key.Proto,
		State:      f.State,
		Midstream:  f.Midstream,
		App:        app,
		Issues:     f.Issues,
		ClientAddr: ca, ClientPort: cp,
		ServerAddr: sa, ServerPort: sp,
		FirstSeen: f.FirstSeen, LastSeen: f.LastSeen,
		PktsOut:  f.InitiatorStats().Packets,
		PktsIn:   f.ResponderStats().Packets,
		BytesOut: f.InitiatorStats().Bytes,
		BytesIn:  f.ResponderStats().Bytes,
	}
}

func dirView(s *DirStats) DirView {
	return DirView{
		Packets: s.Packets, Bytes: s.Bytes, PayloadBytes: s.PayloadBytes,
		Retransmits: s.Seq.Retransmits, DupAcks: s.Seq.DupAcks,
		OutOfOrder: s.Seq.OutOfOrder, ZeroWindows: s.Seq.ZeroWindows,
	}
}

func (f *Flow) detail() FlowDetail {
	d := FlowDetail{
		Row:          f.row(),
		HandshakeRTT: f.HandshakeRTT,
		Midstream:    f.Midstream,
		Out:          dirView(f.InitiatorStats()),
		In:           dirView(f.ResponderStats()),
		Initiator:    f.Initiator,
		Packets:      f.Ring.All(),
	}
	if f.Key.Proto == capture.ProtoICMPv4 || f.Key.Proto == capture.ProtoICMPv6 {
		d.ICMPLabel = analyze.ICMPLabel(f.Key.Proto, f.ICMPType, f.ICMPCode)
	}
	return d
}
