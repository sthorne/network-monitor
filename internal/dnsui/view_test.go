package dnsui

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sthorne/network-monitor/internal/capture"
	"github.com/sthorne/network-monitor/internal/dnsmon"
)

func testModel(width int) *model {
	t0 := time.Unix(1700000000, 0)
	resolver := netip.MustParseAddr("192.0.2.53")
	snap := dnsmon.Snapshot{
		Now:       t0.Add(3 * time.Second),
		Resolvers: []netip.Addr{resolver},
		Rows: []dnsmon.Row{
			{
				Seq:     1,
				Side:    dnsmon.SideClient,
				Proto:   capture.ProtoUDP,
				Querier: netip.MustParseAddr("10.1.0.11"), QuerierPort: 54001,
				Server: resolver, ServerPort: 53,
				QID: 4369, QName: "www.example.com", QType: 1,
				State: dnsmon.TxnAnswered, RCode: 0, Answers: 1,
				QueryTS: t0, RespTS: t0.Add(12 * time.Millisecond),
			},
			{
				Seq:     2,
				Side:    dnsmon.SideUpstream,
				Proto:   capture.ProtoUDP,
				Querier: resolver, QuerierPort: 40001,
				Server: netip.MustParseAddr("199.43.135.53"), ServerPort: 53,
				QID: 8193, QName: "www.example.com", QType: 1,
				State:   dnsmon.TxnTimeout,
				QueryTS: t0.Add(time.Millisecond),
			},
			{
				Seq:     3,
				Side:    dnsmon.SideClient,
				Proto:   capture.ProtoUDP,
				Querier: netip.MustParseAddr("10.1.0.12"), QuerierPort: 55002,
				Server: resolver, ServerPort: 53,
				QID: 4626, QName: "nope.example.com", QType: 28,
				State: dnsmon.TxnAnswered, RCode: 3,
				QueryTS: t0.Add(time.Second), RespTS: t0.Add(time.Second + 5*time.Millisecond),
			},
		},
	}
	m := newModel(Params{Stats: &capture.Stats{}, SourceName: "demo.pcap"})
	m.width, m.height = width, 24
	m.snap = snap
	m.haveSnap = true
	m.split()
	return m
}

func TestViewSplit(t *testing.T) {
	for _, width := range []int{60, 80, 120, 200} {
		m := testModel(width)
		out := m.View()
		wants := []string{
			"CLIENTS → RESOLVER", "RESOLVER → AUTHS",
			"TIMEOUT", "NXDOMAIN", "4369", "8193",
		}
		if width >= 120 {
			// Wide panes must show untruncated addresses and names.
			wants = append(wants, "www.example.com", "10.1.0.11:54001", "199.43.135.53")
		}
		for _, want := range wants {
			if !strings.Contains(out, want) {
				t.Errorf("width %d: view missing %q", width, want)
			}
		}
	}
}

func TestSelectionNewestFirstAndPinning(t *testing.T) {
	m := testModel(120)
	// Left pane: two client rows, newest (nope.example.com, seq 3) first.
	left := m.rows[dnsmon.SideClient]
	if len(left) != 2 || left[0].QName != "nope.example.com" {
		t.Fatalf("left rows = %+v, want newest first", left)
	}
	// Default selection follows the newest row.
	if row, ok := m.selectedRow(); !ok || row.Seq != 3 {
		t.Fatalf("default selection = %+v, want seq 3", row)
	}
	// Moving down pins the older transaction.
	m.moveSel(1)
	if row, _ := m.selectedRow(); row.Seq != 1 || m.selSeq[dnsmon.SideClient] != 1 {
		t.Fatalf("after move: sel=%+v pin=%d, want seq 1 pinned", row, m.selSeq[dnsmon.SideClient])
	}
	// A new snapshot with a fresh row on top keeps the pinned selection.
	newRow := m.snap.Rows[0]
	newRow.Seq, newRow.QueryTS = 9, m.snap.Now
	m.snap.Rows = append(m.snap.Rows, newRow)
	m.split()
	if row, _ := m.selectedRow(); row.Seq != 1 {
		t.Fatalf("after new snapshot: sel=%+v, want still seq 1", row)
	}
	// Moving back to the top re-enters follow mode.
	m.moveSel(-10)
	if m.selSeq[dnsmon.SideClient] != 0 {
		t.Errorf("top selection should unpin (follow mode), pin=%d", m.selSeq[dnsmon.SideClient])
	}
	// Clamping: huge move stays on the last row.
	m.moveSel(99)
	if row, _ := m.selectedRow(); row.Seq != 1 {
		t.Errorf("clamped selection = %+v, want oldest row (seq 1)", row)
	}
}

func TestInspectorView(t *testing.T) {
	m := testModel(140)
	m.height = 48 // tall enough that the response section isn't clipped
	m.inspector = true

	// Query: www.example.com A with EDNS; response: one A answer.
	q := append([]byte{0x11, 0x11, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1},
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	q = append(q, 0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0) // OPT: udp 1232, DO
	r := append([]byte{0x11, 0x11, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0},
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	r = append(r, 0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 93, 184, 216, 34)

	row, _ := m.selectedRow()
	m.detail = dnsmon.TxnDetail{
		Row:      row,
		QueryMsg: q, RespMsg: r,
		QueryWireLen: len(q) + 42, RespWireLen: len(r) + 42,
	}
	m.haveDetail = true

	out := m.View()
	for _, want := range []string{
		"QUERY", "RESPONSE",
		"question:   www.example.com. IN A",
		"edns: version 0 · udp 1232 · DO",
		"answer:     www.example.com.",
		"93.184.216.34",
		"0000  11 11", // hex dump present
	} {
		if !strings.Contains(out, want) {
			t.Errorf("inspector missing %q", want)
		}
	}
	// The inspector shrinks the transaction list, never the layout height.
	if got := strings.Count(out, "\n") + 1; got != m.height {
		t.Errorf("view height = %d lines, want %d", got, m.height)
	}
}

func TestInspectorTimeoutAndPending(t *testing.T) {
	m := testModel(120)
	m.inspector = true
	m.focus = dnsmon.SideUpstream // selected row is the TIMEOUT txn (seq 2)
	row, _ := m.selectedRow()
	m.detail = dnsmon.TxnDetail{Row: row, QueryMsg: []byte{0x20, 0x01, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0}}
	m.haveDetail = true
	if out := m.View(); !strings.Contains(out, "none (timed out)") {
		t.Error("timeout inspector missing 'none (timed out)'")
	}
}

func TestHexDump(t *testing.T) {
	lines := hexDump([]byte("ABCDEFGHIJKLMNOPQR"), 512)
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	if !strings.Contains(lines[0], "41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 50") ||
		!strings.Contains(lines[0], "|ABCDEFGHIJKLMNOP|") {
		t.Errorf("row 0 = %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "0010  51 52") {
		t.Errorf("row 1 = %q", lines[1])
	}
	capped := hexDump(make([]byte, 600), 512)
	if last := capped[len(capped)-1]; !strings.Contains(last, "88 more bytes") {
		t.Errorf("cap note = %q", last)
	}
}

func TestViewHelp(t *testing.T) {
	m := testModel(100)
	m.showHelp = true
	out := m.View()
	if !strings.Contains(out, "recursive resolver") || !strings.Contains(out, "inspector") {
		t.Error("help view missing expected text")
	}
}
