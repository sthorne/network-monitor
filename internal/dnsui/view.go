package dnsui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

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
	styleSelected  = lipgloss.NewStyle().Background(lipgloss.Color("237")).Bold(true)
	styleSelBlur   = lipgloss.NewStyle().Background(lipgloss.Color("235"))
	styleInspRule  = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
	styleNotice    = lipgloss.NewStyle().Foreground(lipgloss.Color("114")).Bold(true)
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
	for i := 0; i < h; i++ {
		b.WriteString(m.renderRow(dnsmon.SideClient, m.scroll[dnsmon.SideClient]+i, lc))
		b.WriteString(div)
		b.WriteString(m.renderRow(dnsmon.SideUpstream, m.scroll[dnsmon.SideUpstream]+i, rc))
		b.WriteByte('\n')
	}

	if m.inspector {
		b.WriteString(m.viewInspector())
		b.WriteByte('\n')
	}

	b.WriteString(m.footer("↑/↓ select · enter inspect · w save packet · J/K panel scroll · tab pane · home follow · c clear done · ? help · q quit"))
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

// renderRow renders row idx of one pane, or a blank line past the end. The
// client pane shows the querier with its source port; the upstream pane
// shows the queried auth server.
func (m *model) renderRow(side dnsmon.Side, idx int, c paneCols) string {
	rows := m.rows[side]
	w := paneWidth(c)
	if idx < 0 || idx >= len(rows) {
		return strings.Repeat(" ", w)
	}
	r := &rows[idx]

	addr := r.Server.String()
	if side == dnsmon.SideClient {
		addr = ui.Endpoint(r.Querier, r.QuerierPort)
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

	if idx == m.sel[side] {
		// Selected rows render unstyled inside a background highlight.
		plain := line + ui.Pad(statusText(r, c.status), c.status)
		if side == m.focus {
			return styleSelected.Render(ui.Pad(plain, w))
		}
		return styleSelBlur.Render(ui.Pad(plain, w))
	}
	return line + statusStyle(r).Render(ui.Pad(statusText(r, c.status), c.status))
}

func paneWidth(c paneCols) int {
	n := 5
	if c.age > 0 {
		n = 6
	}
	return c.age + c.addr + c.qname + c.qtype + c.qid + c.status + (n - 1)
}

// statusText renders the transaction outcome for a cell of the given width.
func statusText(r *dnsmon.Row, width int) string {
	switch r.State {
	case dnsmon.TxnPending:
		return "…"
	case dnsmon.TxnTimeout:
		return "TIMEOUT"
	}
	rcode := dnsmon.RCodeName(r.RCode)
	if r.TC {
		rcode += "+TC"
	}
	if width >= 14 {
		return ui.Age(r.Latency()) + " " + rcode
	}
	return rcode
}

// statusStyle picks the severity color for the outcome cell.
func statusStyle(r *dnsmon.Row) lipgloss.Style {
	switch r.State {
	case dnsmon.TxnPending:
		return styleDim
	case dnsmon.TxnTimeout:
		return styleBad
	}
	switch r.RCode {
	case 0:
		return styleGood
	case 2, 5: // SERVFAIL, REFUSED
		return styleBad
	default:
		return styleWarn
	}
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
	if m.notice != "" && time.Since(m.noticeAt) < 5*time.Second {
		return styleNotice.Render(ui.Truncate(" "+m.notice, m.width))
	}
	return styleFooter.Render(ui.Truncate(" "+hints, m.width))
}
