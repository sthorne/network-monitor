package flow

import (
	"testing"
	"time"

	"github.com/sthorne/network-monitor/internal/analyze"
	"github.com/sthorne/network-monitor/internal/capture"
)

const (
	client = DirAtoB
	server = DirBtoA
)

type step struct {
	dir   Dir
	flags capture.TCPFlags
	want  TCPState
}

func runSteps(t *testing.T, steps []step) *Flow {
	t.Helper()
	f := &Flow{Initiator: client}
	ts := time.Unix(1000, 0)
	for i, s := range steps {
		ts = ts.Add(10 * time.Millisecond)
		f.applyTCPState(s.dir, s.flags, ts)
		if f.State != s.want {
			t.Fatalf("step %d (%v %v): state = %v, want %v", i, s.dir, s.flags, f.State, s.want)
		}
	}
	return f
}

func TestHandshakeAndClose(t *testing.T) {
	f := runSteps(t, []step{
		{client, capture.FlagSYN, StateSynSent},
		{server, capture.FlagSYN | capture.FlagACK, StateSynRecv},
		{client, capture.FlagACK, StateEstab},
		{client, capture.FlagACK | capture.FlagPSH, StateEstab},
		{client, capture.FlagFIN | capture.FlagACK, StateFinWait},
		{server, capture.FlagACK, StateFinWait},
		{server, capture.FlagFIN | capture.FlagACK, StateClosing},
		{client, capture.FlagACK, StateClosed},
	})
	if f.HandshakeRTT <= 0 {
		t.Errorf("handshake RTT not recorded")
	}
	if f.Midstream {
		t.Errorf("clean handshake marked midstream")
	}
	if f.ClosedAt.IsZero() {
		t.Errorf("ClosedAt not set")
	}
}

func TestConnectionRefused(t *testing.T) {
	f := runSteps(t, []step{
		{client, capture.FlagSYN, StateSynSent},
		{server, capture.FlagRST | capture.FlagACK, StateReset},
	})
	if f.Issues&analyze.IssueConnRefused == 0 {
		t.Errorf("SYN→RST did not flag connection refused")
	}
}

func TestRSTFromEstablished(t *testing.T) {
	f := runSteps(t, []step{
		{client, capture.FlagSYN, StateSynSent},
		{server, capture.FlagSYN | capture.FlagACK, StateSynRecv},
		{client, capture.FlagACK, StateEstab},
		{client, capture.FlagRST, StateReset},
	})
	if f.Issues&analyze.IssueConnRefused != 0 {
		t.Errorf("mid-stream RST wrongly flagged as refused")
	}
}

func TestMidstreamPickup(t *testing.T) {
	f := runSteps(t, []step{
		{client, capture.FlagACK | capture.FlagPSH, StateEstab},
	})
	if !f.Midstream {
		t.Errorf("no-handshake flow not marked midstream")
	}
}

func TestSimultaneousFin(t *testing.T) {
	runSteps(t, []step{
		{client, capture.FlagSYN, StateSynSent},
		{server, capture.FlagSYN | capture.FlagACK, StateSynRecv},
		{client, capture.FlagACK, StateEstab},
		{client, capture.FlagFIN | capture.FlagACK, StateFinWait},
		{server, capture.FlagFIN | capture.FlagACK, StateClosing},
		{client, capture.FlagACK, StateClosed},
	})
}

func TestSynAckFirstSetsInitiator(t *testing.T) {
	// Capture joins between SYN and SYN|ACK: the SYN|ACK sender is the server.
	f := &Flow{Initiator: server} // first observed packet came from the server side
	ts := time.Unix(1000, 0)
	f.applyTCPState(server, capture.FlagSYN|capture.FlagACK, ts)
	if f.State != StateSynRecv {
		t.Fatalf("state = %v, want SYN_RECV", f.State)
	}
	if f.Initiator != client {
		t.Errorf("initiator = %v, want the non-SYN|ACK side", f.Initiator)
	}
}
