package ui

import (
	"fmt"
	"strings"
)

func (m *model) viewTopTalkers() string {
	var b strings.Builder
	b.WriteString(m.statusBar())
	b.WriteByte('\n')

	var lines []string
	lines = append(lines, "")
	lines = append(lines, "  "+styleTitle.Render("TOP 10 CLIENTS")+
		styleDim.Render(fmt.Sprintf("   (of %s total)", Bytes(m.snap.TotalBytes))))
	lines = append(lines, "")
	lines = append(lines, "  "+styleColHeader.Render(
		Pad("#", 4)+Pad("CLIENT", 42)+PadLeft("FLOWS", 7)+PadLeft("PACKETS", 12)+PadLeft("BYTES", 12)+"  "+Pad("SHARE", 24)))

	barWidth := 20
	for i, h := range m.snap.TopHosts {
		pct := 0.0
		if m.snap.TotalBytes > 0 {
			pct = float64(h.Bytes) / float64(m.snap.TotalBytes)
		}
		filled := int(pct*float64(barWidth) + 0.5)
		if filled > barWidth {
			filled = barWidth
		}
		bar := styleBar.Render(strings.Repeat("█", filled)) + styleDim.Render(strings.Repeat("░", barWidth-filled))
		lines = append(lines, fmt.Sprintf("  %s%s%s%s%s  %s %4.1f%%",
			Pad(fmt.Sprintf("%d.", i+1), 4),
			Pad(h.Addr.String(), 42),
			PadLeft(fmt.Sprint(h.Flows), 7),
			PadLeft(fmt.Sprint(h.Packets), 12),
			PadLeft(Bytes(h.Bytes), 12),
			bar, pct*100))
	}
	if len(m.snap.TopHosts) == 0 {
		lines = append(lines, styleDim.Render("    no traffic yet"))
	}

	h := m.bodyHeight()
	for i := 0; i < h; i++ {
		if i < len(lines) {
			b.WriteString(lines[i])
		}
		b.WriteByte('\n')
	}
	b.WriteString(m.footer("t/esc back to flows · p pause · ? help · q quit"))
	return b.String()
}
