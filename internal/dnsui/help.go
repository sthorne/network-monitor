package dnsui

import (
	"strings"

	"github.com/sthorne/network-monitor/internal/ui"
)

func (m *model) viewHelp() string {
	lines := []string{
		"",
		"  dnsmon — DNS transactions from a recursive resolver's perspective",
		"",
		"  The left pane shows queries arriving from clients at the resolver;",
		"  the right pane shows the queries the resolver sends to upstream or",
		"  authoritative servers. Each row is one query/response transaction:",
		"  who asked, the qname, qtype, DNS message ID, and the outcome",
		"  (latency + rcode, pending …, or TIMEOUT).",
		"",
		"  The resolver identity comes from --resolver, or is auto-detected:",
		"  an address seen both receiving and sending DNS queries. Until one",
		"  is identified, all transactions are shown on the client side.",
		"",
		"  keys",
		"    tab ← → h l   switch pane",
		"    ↑/↓ j/k       select a transaction (newest first)",
		"    pgup/pgdn     page the selection",
		"    home          jump back to newest (follow mode)",
		"    enter i       toggle the inspector: full decode + hex of the",
		"                  selected transaction, shown at the bottom",
		"    J/K           scroll the inspector panel",
		"    w             save the selected transaction's packets to a pcap",
		"                  (query + response frames, opens in Wireshark)",
		"    p             pause display updates",
		"    c             clear answered and timed-out transactions",
		"    ?             toggle this help",
		"    q             quit",
		"",
		"  press any key to close",
	}
	var b strings.Builder
	b.WriteString(m.statusBar())
	b.WriteByte('\n')
	for _, l := range lines {
		b.WriteString(ui.Truncate(l, m.width))
		b.WriteByte('\n')
	}
	return b.String()
}
