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
				Side:    dnsmon.SideClient,
				Proto:   capture.ProtoUDP,
				Querier: netip.MustParseAddr("10.1.0.11"), QuerierPort: 54001,
				Server: resolver, ServerPort: 53,
				QID: 4369, QName: "www.example.com", QType: 1,
				State: dnsmon.TxnAnswered, RCode: 0, Answers: 1,
				QueryTS: t0, RespTS: t0.Add(12 * time.Millisecond),
			},
			{
				Side:    dnsmon.SideUpstream,
				Proto:   capture.ProtoUDP,
				Querier: resolver, QuerierPort: 40001,
				Server: netip.MustParseAddr("199.43.135.53"), ServerPort: 53,
				QID: 8193, QName: "www.example.com", QType: 1,
				State:   dnsmon.TxnTimeout,
				QueryTS: t0.Add(time.Millisecond),
			},
			{
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
	m.width, m.height = width, 20
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

func TestViewNewestFirstAndScroll(t *testing.T) {
	m := testModel(120)
	// Left pane: two client rows, newest (nope.example.com) first.
	left := m.rows[dnsmon.SideClient]
	if len(left) != 2 || left[0].QName != "nope.example.com" {
		t.Fatalf("left rows = %+v, want newest first", left)
	}
	m.focus = dnsmon.SideClient
	m.scrollBy(5) // clamps to last row
	if m.scroll[dnsmon.SideClient] != 1 {
		t.Errorf("scroll = %d, want clamped to 1", m.scroll[dnsmon.SideClient])
	}
	m.scrollBy(-10)
	if m.scroll[dnsmon.SideClient] != 0 {
		t.Errorf("scroll = %d, want 0", m.scroll[dnsmon.SideClient])
	}
}

func TestViewHelp(t *testing.T) {
	m := testModel(100)
	m.showHelp = true
	out := m.View()
	if !strings.Contains(out, "recursive resolver") || !strings.Contains(out, "switch pane") {
		t.Error("help view missing expected text")
	}
}
