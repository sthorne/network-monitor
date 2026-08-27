package dnsui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/sthorne/network-monitor/internal/dnsmon"
	"github.com/sthorne/network-monitor/internal/ui"
)

var (
	styleStatusBar = lipgloss.NewStyle().
			Foreground(lipgloss.Color("230")).
			Background(lipgloss.Color("24"))
	styleColHeader = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Bold(true)
	styleFooter    = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	styleTitle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("81"))
	styleTitleBlur = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("243"))
	styleDim       = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	styleGood      = lipgloss.NewStyle().Foreground(lipgloss.Color("114"))
	styleWarn      = lipgloss.NewStyle().Foreground(lipgloss.Color("221"))
	styleBad       = lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Bold(true)
	stylePaused    = lipgloss.NewStyle().Foreground(lipgloss.Color("221")).Bold(true)
	styleDivider   = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

// paneCols is the column layout inside one pane. age is 0 when the pane is
// too narrow to show it.
type paneCols struct {
	age, addr, qname, qtype, qid, status int
}

func computeCols(w int) paneCols {
	c := paneCols{age: 5, qtype: 5, qid: 5, status: 14}
	if w < 72 {
		c.status = 8 // rcode only, no latency
	}
	if w < 64 {
		c.age = 0
	}
	ncols := 5
	if c.age > 0 {
		ncols = 6
	}
	fixed := c.age + c.qtype + c.qid + c.status + (ncols - 1)
	rest := w - fixed
	if rest < 8 {
		rest = 8
	}
	// 45% to the address (an IPv4 client with port needs 15-21 cells), the
	// rest to the qname.
	c.addr = rest * 45 / 100
	if c.addr > 22 {
		c.addr = 22
	}
	if c.addr < 9 {
		c.addr = 9
	}
	c.qname = rest - c.addr
	if c.qname < 6 {
		c.qname = 6
	}
	return c
}

func (m *model) viewSplit() string {
	var b strings.Builder
	lw := (m.width - 1) / 2
	rw := m.width - 1 - lw
	div := styleDivider.Render("│")

	b.WriteString(m.statusBar())
	b.WriteByte('\n')

	// Pane titles.
	lt := fmt.Sprintf(" CLIENTS → RESOLVER  %d txns", len(m.rows[dnsmon.SideClient]))
	rt := fmt.Sprintf(" RESOLVER → AUTHS  %d txns", len(m.rows[dnsmon.SideUpstream]))
	ls, rs := styleTitleBlur, styleTitleBlur
	if m.focus == dnsmon.SideClient {
		ls = styleTitle
	} else {
		rs = styleTitle
	}
	b.WriteString(ls.Render(ui.Pad(lt, lw)))
	b.WriteString(div)
	b.WriteString(rs.Render(ui.Pad(rt, rw)))
	b.WriteByte('\n')

	// Column headers.
	lc, rc := computeCols(lw), computeCols(rw)
	b.WriteString(styleColHeader.Render(header(lc, "CLIENT")))
	b.WriteString(div)
	b.WriteString(styleColHeader.Render(header(rc, "AUTH SERVER")))
	b.WriteByte('\n')

	h := m.listHeight()
	left, right := m.rows[dnsmon.SideClient], m.rows[dnsmon.SideUpstream]
	for i := 0; i < h; i++ {
		b.WriteString(m.renderRow(left, m.scroll[dnsmon.SideClient]+i, lc, true))
		b.WriteString(div)
		b.WriteString(m.renderRow(right, m.scroll[dnsmon.SideUpstream]+i, rc, false))
		b.WriteByte('\n')
	}

	b.WriteString(m.footer("tab/←/→ pane · ↑/↓ scroll · home follow · p pause · c clear done · ? help · q quit"))
	return b.String()
}

func header(c paneCols, addrLabel string) string {
	var parts []string
	if c.age > 0 {
		parts = append(parts, ui.PadLeft("AGE", c.age))
	}
	parts = append(parts,
		ui.Pad(addrLabel, c.addr),
		ui.Pad("QNAME", c.qname),
		ui.Pad("TYPE", c.qtype),
		ui.PadLeft("QID", c.qid),
		ui.Pad("STATUS", c.status))
	return strings.Join(parts, " ")
}

// renderRow renders row idx of one pane, or a blank line past the end.
// withPort shows the querier's source port (meaningful on the client side).
func (m *model) renderRow(rows []dnsmon.Row, idx int, c paneCols, withPort bool) string {
	w := paneWidth(c)
	if idx < 0 || idx >= len(rows) {
		return strings.Repeat(" ", w)
	}
	r := &rows[idx]

	addr := r.Querier.String()
	if withPort {
		addr = ui.Endpoint(r.Querier, r.QuerierPort)
	} else {
		// Upstream pane: the interesting address is the queried auth server.
		addr = r.Server.String()
	}

	var parts []string
	if c.age > 0 {
		parts = append(parts, ui.PadLeft(ui.Age(m.snap.Now.Sub(r.QueryTS)), c.age))
	}
	parts = append(parts,
		ui.Pad(addr, c.addr),
		ui.Pad(r.QName, c.qname),
		ui.Pad(dnsmon.TypeName(r.QType), c.qtype),
		ui.PadLeft(strconv.Itoa(int(r.QID)), c.qid))
	line := strings.Join(parts, " ") + " "
	return line + statusCell(r, c.status)
}

func paneWidth(c paneCols) int {
	n := 5
	if c.age > 0 {
		n = 6
	}
	return c.age + c.addr + c.qname + c.qtype + c.qid + c.status + (n - 1)
}

// statusCell renders the transaction outcome, styled by severity.
func statusCell(r *dnsmon.Row, width int) string {
	switch r.State {
	case dnsmon.TxnPending:
		return styleDim.Render(ui.Pad("…", width))
	case dnsmon.TxnTimeout:
		return styleBad.Render(ui.Pad("TIMEOUT", width))
	}
	rcode := dnsmon.RCodeName(r.RCode)
	if r.TC {
		rcode += "+TC"
	}
	text := rcode
	if width >= 14 {
		text = ui.Age(r.Latency()) + " " + rcode
	}
	st := styleGood
	switch r.RCode {
	case 3: // NXDOMAIN
		st = styleWarn
	case 2, 5: // SERVFAIL, REFUSED
		st = styleBad
	default:
		if r.RCode != 0 {
			st = styleWarn
		}
	}
	return st.Render(ui.Pad(text, width))
}

func (m *model) statusBar() string {
	mode := "LIVE " + m.p.SourceName
	if !m.p.Live {
		mode = "FILE " + m.p.SourceName
		if m.snap.EOF {
			mode += " (EOF)"
		}
	}
	cs := m.snap.Sides[dnsmon.SideClient]
	us := m.snap.Sides[dnsmon.SideUpstream]
	parts := []string{
		" dnsmon",
		mode,
		"resolver " + resolverLabel(m.snap),
		fmt.Sprintf("cli %dq %da", cs.Queries, cs.Answered),
		fmt.Sprintf("auth %dq %da", us.Queries, us.Answered),
	}
	if to := cs.Timeout + us.Timeout; to > 0 {
		parts = append(parts, fmt.Sprintf("t-o %d", to))
	}
	if m.p.Live {
		parts = append(parts, fmt.Sprintf("%.0f qps", m.qps))
	}
	if m.snap.Orphans > 0 {
		parts = append(parts, fmt.Sprintf("orphan %d", m.snap.Orphans))
	}
	if dropped := m.p.Stats.Dropped.Load(); dropped > 0 {
		parts = append(parts, fmt.Sprintf("drop %d", dropped))
	}
	line := strings.Join(parts, " │ ")
	if m.paused {
		return styleStatusBar.Render(ui.Pad(line+" │ ", m.width-7)) + stylePaused.Render("PAUSED ")
	}
	return styleStatusBar.Render(ui.Pad(line, m.width))
}

func resolverLabel(s dnsmon.Snapshot) string {
	switch len(s.Resolvers) {
	case 0:
		return "auto?"
	case 1:
		return s.Resolvers[0].String()
	default:
		return fmt.Sprintf("%s +%d", s.Resolvers[0], len(s.Resolvers)-1)
	}
}

func (m *model) footer(hints string) string {
	return styleFooter.Render(ui.Truncate(" "+hints, m.width))
}
