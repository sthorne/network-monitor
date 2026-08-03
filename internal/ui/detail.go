package ui

import (
	"fmt"
	"strings"

	"github.com/sthorne/network-monitor/internal/capture"
	"github.com/sthorne/network-monitor/internal/flow"
)

func (m *model) viewDetail() string {
	var b strings.Builder
	b.WriteString(m.statusBar())
	b.WriteByte('\n')

	if !m.haveDetail {
		b.WriteString("\n  loading flow…\n")
		for i := 0; i < m.bodyHeight()-3; i++ {
			b.WriteByte('\n')
		}
		b.WriteString(m.footer("esc back · q quit"))
		return b.String()
	}

	lines := m.detailLines()
	h := m.bodyHeight()
	maxScroll := len(lines) - h
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.detailScroll > maxScroll {
		m.detailScroll = maxScroll
	}
	end := m.detailScroll + h
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[m.detailScroll:end] {
		b.WriteString(Truncate(l, m.width))
		b.WriteByte('\n')
	}
	for i := end - m.detailScroll; i < h; i++ {
		b.WriteByte('\n')
	}
	b.WriteString(m.footer("↑/↓ scroll · esc back · q quit"))
	return b.String()
}

func (m *model) detailLines() []string {
	d := &m.detail
	r := &d.Row
	var out []string
	add := func(s string) { out = append(out, s) }

	add("")
	add("  " + styleTitle.Render(fmt.Sprintf("%s  %s → %s",
		strings.ToUpper(r.Proto.String()),
		Endpoint(r.ClientAddr, r.ClientPort),
		Endpoint(r.ServerAddr, r.ServerPort))))
	add("")

	state := stateStyle(r.State).Render(r.State.String())
	if d.Midstream {
		state += styleDim.Render("  (picked up mid-stream)")
	}
	add("  State:         " + state)
	app := r.App.Label()
	if d.ICMPLabel != "" {
		app = d.ICMPLabel
	}
	add("  Application:   " + app)
	dur := r.LastSeen.Sub(r.FirstSeen)
	add(fmt.Sprintf("  Duration:      %s   (idle %s)", Age(dur), Age(m.snap.Now.Sub(r.LastSeen))))
	if d.HandshakeRTT > 0 {
		add("  Handshake RTT: " + Age(d.HandshakeRTT))
	}
	add("")

	add("  " + styleColHeader.Render(Pad("DIRECTION", 22)+PadLeft("PKTS", 10)+PadLeft("BYTES", 12)+
		PadLeft("PAYLOAD", 12)+PadLeft("RETRANS", 9)+PadLeft("DUPACK", 8)+PadLeft("OOO", 6)+PadLeft("0-WIN", 7)))
	dirLine := func(label string, v flow.DirView) string {
		return "  " + Pad(label, 22) + PadLeft(fmt.Sprint(v.Packets), 10) +
			PadLeft(Bytes(v.Bytes), 12) + PadLeft(Bytes(v.PayloadBytes), 12) +
			PadLeft(fmt.Sprint(v.Retransmits), 9) + PadLeft(fmt.Sprint(v.DupAcks), 8) +
			PadLeft(fmt.Sprint(v.OutOfOrder), 6) + PadLeft(fmt.Sprint(v.ZeroWindows), 7)
	}
	add(dirLine("client → server", d.Out))
	add(dirLine("server → client", d.In))
	add("")

	if names := r.Issues.Names(); len(names) > 0 {
		add("  " + styleIssue.Render("Issues:"))
		for _, n := range names {
			add("    " + styleIssue.Render("• "+n))
		}
	} else {
		add("  " + styleGood.Render("No issues detected"))
	}
	add("")

	add("  " + styleColHeader.Render(fmt.Sprintf("PACKET TIMELINE (last %d)", len(d.Packets))))
	if len(d.Packets) == 0 {
		add(styleDim.Render("    no packets recorded"))
	}
	start := r.FirstSeen
	for i := range d.Packets {
		p := &d.Packets[i]
		arrow := "→"
		if p.Dir != d.Initiator {
			arrow = "←"
		}
		line := fmt.Sprintf("  %s  %s  ", PadLeft("+"+Age(p.TS.Sub(start)), 10), arrow)
		if r.Proto == capture.ProtoTCP {
			line += Pad(p.Flags.String(), 16) + fmt.Sprintf("len=%-6d win=%-6d seq=%d", p.Len, p.Window, p.RelSeq)
		} else {
			line += fmt.Sprintf("len=%d", p.Len)
		}
		if p.Note != 0 {
			line += "  " + styleIssue.Render("["+p.Note.String()+"]")
		}
		add(line)
	}
	return out
}
