package flow

import (
	"time"

	"github.com/sthorne/network-monitor/internal/analyze"
	"github.com/sthorne/network-monitor/internal/capture"
)

// applyTCPState advances the flow's observed TCP state for one segment.
// This is a passive-observer simplification of RFC 793: we track the
// conversation as a whole, not each endpoint's TCB.
func (f *Flow) applyTCPState(dir Dir, flags capture.TCPFlags, ts time.Time) {
	fromInit := dir == f.Initiator

	if flags.Has(capture.FlagRST) {
		if f.State == StateSynSent && !fromInit {
			f.Issues |= analyze.IssueConnRefused
		}
		f.setState(StateReset, ts)
		return
	}

	switch f.State {
	case StateUnknown:
		switch {
		case flags.Has(capture.FlagSYN) && !flags.Has(capture.FlagACK):
			// First SYN defines the initiator.
			f.Initiator = dir
			f.SynTime = ts
			f.setState(StateSynSent, ts)
		case flags.Has(capture.FlagSYN) && flags.Has(capture.FlagACK):
			// Joined just after the first SYN: the SYN|ACK sender is the responder.
			f.Initiator = dir.Reverse()
			f.SynAckTime = ts
			f.Midstream = true
			f.setState(StateSynRecv, ts)
		default:
			// Mid-stream pickup: no handshake observed.
			f.Midstream = true
			f.setState(StateEstab, ts)
		}
	case StateSynSent:
		if !fromInit && flags.Has(capture.FlagSYN) && flags.Has(capture.FlagACK) {
			f.SynAckTime = ts
			f.setState(StateSynRecv, ts)
		}
	case StateSynRecv:
		if fromInit && flags.Has(capture.FlagACK) && !flags.Has(capture.FlagSYN) {
			if !f.SynTime.IsZero() && !f.SynAckTime.IsZero() {
				f.HandshakeRTT = f.SynAckTime.Sub(f.SynTime)
			}
			f.setState(StateEstab, ts)
		}
	}

	if flags.Has(capture.FlagFIN) {
		f.finSeen[dir] = true
		switch {
		case f.finSeen[0] && f.finSeen[1]:
			if f.State != StateClosed {
				f.setState(StateClosing, ts)
			}
		case f.State == StateEstab || f.State == StateSynRecv:
			f.setState(StateFinWait, ts)
		}
		return
	}

	// Any ACK after both FINs completes the close (approximation of the
	// final ACK of the four-way teardown).
	if f.State == StateClosing && flags.Has(capture.FlagACK) {
		f.setState(StateClosed, ts)
	}
}

func (f *Flow) setState(s TCPState, ts time.Time) {
	if f.State == s {
		return
	}
	f.State = s
	if s.Terminal() {
		f.ClosedAt = ts
	}
}
