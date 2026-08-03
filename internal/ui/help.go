package ui

import "strings"

func (m *model) viewHelp() string {
	var b strings.Builder
	b.WriteString(m.statusBar())
	b.WriteByte('\n')

	lines := []string{
		"",
		"  " + styleTitle.Render("netmon — key bindings"),
		"",
		"  ↑/↓, j/k        select flow / scroll",
		"  PgUp/PgDn       page",
		"  enter           analyze selected flow",
		"  esc             back",
		"  t               toggle Top 10 clients view",
		"  s               cycle sort (activity → bytes → duration → first-seen → state)",
		"  o               reverse sort order",
		"  p               pause display (capture continues)",
		"  c               clear closed flows",
		"  ?               this help",
		"  q, ctrl+c       quit",
		"",
		"  " + styleColHeader.Render("Columns"),
		"  STATE           observed TCP state (SYN_SENT, ESTAB, FIN_WAIT, RST, …)",
		"  APP             identified application protocol; a trailing ? means",
		"                  the guess came from the port, not the payload",
		"  PKTS/BYTES ⇄    client→server / server→client",
		"  !               flow has detected issues — press enter for details",
		"",
		"  press any key to close",
	}
	h := m.bodyHeight()
	for i := 0; i < h; i++ {
		if i < len(lines) {
			b.WriteString(Truncate(lines[i], m.width))
		}
		b.WriteByte('\n')
	}
	b.WriteString(m.footer(""))
	return b.String()
}
