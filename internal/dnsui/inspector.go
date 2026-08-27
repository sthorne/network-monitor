package dnsui

import (
	"fmt"
	"strings"
	"time"

	"github.com/sthorne/network-monitor/internal/capture"
	"github.com/sthorne/network-monitor/internal/dnsmon"
	"github.com/sthorne/network-monitor/internal/ui"
)

// maxHexBytes bounds the hex dump per message in the inspector.
const maxHexBytes = 512

// viewInspector renders the bottom panel: a summary separator line plus the
// scrollable decode/hex body, exactly inspectorHeight() lines tall.
func (m *model) viewInspector() string {
	var b strings.Builder
	h := m.inspectorHeight()

	title := " no transaction selected "
	if row, ok := m.selectedRow(); ok {
		title = " " + txnSummary(&row) + " "
	}
	rule := "─" + title
	if pad := m.width - len([]rune(rule)); pad > 0 {
		rule += strings.Repeat("─", pad)
	}
	b.WriteString(styleInspRule.Render(ui.Truncate(rule, m.width)))
	b.WriteByte('\n')

	lines := m.inspectorLines()
	body := h - 1
	maxScroll := len(lines) - body
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.inspScroll > maxScroll {
		m.inspScroll = maxScroll
	}
	for i := 0; i < body; i++ {
		idx := m.inspScroll + i
		if idx < len(lines) {
			b.WriteString(ui.Truncate(lines[idx], m.width))
		}
		if i < body-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func txnSummary(r *dnsmon.Row) string {
	who := "client"
	if r.Side == dnsmon.SideUpstream {
		who = "resolver"
	}
	s := fmt.Sprintf("%s %s → %s · %s · qid %d · %s %s",
		who,
		ui.Endpoint(r.Querier, r.QuerierPort),
		ui.Endpoint(r.Server, r.ServerPort),
		r.Proto, r.QID, r.QName, dnsmon.TypeName(r.QType))
	switch r.State {
	case dnsmon.TxnAnswered:
		s += fmt.Sprintf(" · answered %s %s", ui.Age(r.Latency()), dnsmon.RCodeName(r.RCode))
	case dnsmon.TxnTimeout:
		s += " · TIMEOUT"
	default:
		s += " · pending"
	}
	if r.Retries > 0 {
		s += fmt.Sprintf(" · retries %d", r.Retries)
	}
	return s
}

// inspectorLines builds the full (unscrolled) body for the selected
// transaction: descriptive decode plus hex for the query and, when captured,
// the response.
func (m *model) inspectorLines() []string {
	row, ok := m.selectedRow()
	if !ok {
		return []string{"  select a transaction with ↑/↓"}
	}
	if !m.haveDetail || m.detail.Seq != row.Seq {
		return []string{"  loading…"}
	}
	d := &m.detail
	fromTCP := d.Proto == capture.ProtoTCP

	var out []string
	out = append(out, msgLines("QUERY", d.QueryMsg, d.QueryWireLen, fromTCP,
		d.QueryTS.Format("2006-01-02 15:04:05.000000"))...)
	if len(d.RespMsg) > 0 {
		out = append(out, "")
		out = append(out, msgLines("RESPONSE", d.RespMsg, d.RespWireLen, fromTCP,
			fmt.Sprintf("+%s", ui.Age(d.RespTS.Sub(d.QueryTS))))...)
	} else if d.State == dnsmon.TxnTimeout {
		out = append(out, "", " RESPONSE  none (timed out)")
	} else if d.State == dnsmon.TxnPending {
		out = append(out, "", " RESPONSE  none yet (pending)")
	}
	return out
}

// msgLines renders one DNS message: dig-style header/section summary followed
// by a hex dump.
func msgLines(label string, wire []byte, wireLen int, fromTCP bool, when string) []string {
	var out []string
	size := fmt.Sprintf("%d bytes", len(wire))
	if wireLen > 0 {
		size = fmt.Sprintf("%d bytes (%dB frame on wire)", len(wire), wireLen)
	}
	out = append(out, fmt.Sprintf(" %s  %s · %s", label, size, when))

	det, ok := dnsmon.DecodeDetail(wire, fromTCP)
	if !ok {
		out = append(out, "  ;; not decodable as DNS")
	} else {
		out = append(out, fmt.Sprintf("  ;; opcode %s · status %s · id %d · flags [%s] · qd %d an %d ns %d ar %d",
			dnsmon.OpcodeName(det.Opcode), dnsmon.RCodeName(det.RCode), det.ID,
			det.FlagString(), det.QDCount, det.ANCount, det.NSCount, det.ARCount))
		for _, q := range det.Questions {
			out = append(out, fmt.Sprintf("  ;; question:   %s. %s %s",
				q.Name, dnsmon.ClassName(q.Class), dnsmon.TypeName(q.Type)))
		}
		if det.EDNS.Present {
			do := ""
			if det.EDNS.DO {
				do = " · DO"
			}
			out = append(out, fmt.Sprintf("  ;; edns: version %d · udp %d%s",
				det.EDNS.Version, det.EDNS.UDPSize, do))
		}
		out = append(out, rrLines("answer", det.Answers)...)
		out = append(out, rrLines("authority", det.Authority)...)
		out = append(out, rrLines("additional", det.Additional)...)
		if det.Truncated {
			out = append(out, "  ;; (decode truncated)")
		}
	}

	for _, l := range hexDump(wire, maxHexBytes) {
		out = append(out, "  "+l)
	}
	return out
}

func rrLines(section string, rrs []dnsmon.RR) []string {
	var out []string
	for _, rr := range rrs {
		out = append(out, fmt.Sprintf("  ;; %-11s %s. %s %s %s %s",
			section+":", rr.Name, formatTTL(rr.TTL),
			dnsmon.ClassName(rr.Class), dnsmon.TypeName(rr.Type), rr.Data))
	}
	return out
}

func formatTTL(ttl uint32) string {
	return ui.Age(time.Duration(ttl) * time.Second)
}
