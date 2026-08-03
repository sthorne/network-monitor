package ui

import (
	"fmt"
	"strings"

	"github.com/sthorne/network-monitor/internal/flow"
)

// Column layout for the flow list. Endpoint columns flex with terminal width.
type flowCols struct {
	proto, endpoint, state, app, age, idle, pkts, bytes, issue int
}

func (m *model) flowCols() flowCols {
	c := flowCols{proto: 5, state: 8, app: 18, age: 7, idle: 7, pkts: 11, bytes: 15, issue: 2}
	fixed := c.proto + c.state + c.app + c.age + c.idle + c.pkts + c.bytes + c.issue +
		3 /* arrow */ + 8 /* separators */
	ep := (m.width - fixed) / 2
	if ep < 17 {
		ep = 17
	}
	if ep > 46 {
		ep = 46
	}
	c.endpoint = ep
	return c
}

func (m *model) viewFlowList() string {
	var b strings.Builder
	c := m.flowCols()

	b.WriteString(m.statusBar())
	b.WriteByte('\n')

	header := fmt.Sprintf("%s %s %s %s %s %s %s %s %s %s",
		Pad("PROTO", c.proto),
		Pad("CLIENT", c.endpoint),
		Pad("→  SERVER", c.endpoint+3),
		Pad("STATE", c.state),
		Pad("APP", c.app),
		PadLeft("AGE", c.age),
		PadLeft("IDLE", c.idle),
		PadLeft("PKTS ⇄", c.pkts),
		PadLeft("BYTES ⇄", c.bytes),
		Pad("!", c.issue))
	b.WriteString(styleColHeader.Render(Pad(header, m.width)))
	b.WriteByte('\n')

	h := m.listHeight()
	end := m.scroll + h
	if end > len(m.rows) {
		end = len(m.rows)
	}
	lines := 0
	for i := m.scroll; i < end; i++ {
		b.WriteString(m.renderFlowRow(&m.rows[i], c, i == m.selIdx))
		b.WriteByte('\n')
		lines++
	}
	for ; lines < h; lines++ {
		b.WriteByte('\n')
	}

	b.WriteString(m.footer("↑/↓ select · enter analyze · t top clients · s sort · o order · p pause · c clear closed · ? help · q quit"))
	return b.String()
}

func (m *model) renderFlowRow(r *flow.FlowRow, c flowCols, selected bool) string {
	age := Age(m.snap.Now.Sub(r.FirstSeen))
	idle := Age(m.snap.Now.Sub(r.LastSeen))
	pkts := fmt.Sprintf("%d/%d", r.PktsOut, r.PktsIn)
	bytes := fmt.Sprintf("%s/%s", Bytes(r.BytesOut), Bytes(r.BytesIn))

	issue := " "
	if r.Issues != 0 {
		issue = "!"
	}
	app := r.App.Label()
	if app == "-" && r.Midstream {
		app = "…"
	}

	plain := fmt.Sprintf("%s %s %s ",
		Pad(r.Proto.String(), c.proto),
		Pad(Endpoint(r.ClientAddr, r.ClientPort), c.endpoint),
		Pad("→  "+Endpoint(r.ServerAddr, r.ServerPort), c.endpoint+3))

	stateCell := Pad(r.State.String(), c.state)
	rest := fmt.Sprintf(" %s %s %s %s %s ",
		Pad(app, c.app),
		PadLeft(age, c.age),
		PadLeft(idle, c.idle),
		PadLeft(pkts, c.pkts),
		PadLeft(bytes, c.bytes))

	if selected {
		line := plain + stateCell + rest + Pad(issue, c.issue)
		return styleSelected.Render(Pad(line, m.width))
	}
	styledState := stateStyle(r.State).Render(stateCell)
	styledIssue := issue
	if issue == "!" {
		styledIssue = styleIssue.Render(Pad(issue, c.issue))
	} else {
		styledIssue = Pad(issue, c.issue)
	}
	return plain + styledState + rest + styledIssue
}

func (m *model) statusBar() string {
	mode := "LIVE " + m.p.SourceName
	if !m.p.Live {
		mode = "FILE " + m.p.SourceName
		if m.snap.EOF {
			mode += " (EOF)"
		}
	}
	dropped := m.p.Stats.Dropped.Load()
	parts := []string{
		" netmon",
		mode,
		fmt.Sprintf("flows %d", m.snap.ActiveFlows),
		fmt.Sprintf("pkts %d", m.snap.TotalPkts),
		fmt.Sprintf("%s", Bytes(m.snap.TotalBytes)),
	}
	if m.p.Live {
		parts = append(parts, fmt.Sprintf("%.0f pps", m.pps))
	}
	if dropped > 0 {
		parts = append(parts, fmt.Sprintf("drop %d", dropped))
	}
	order := "▼"
	if m.sortAsc {
		order = "▲"
	}
	parts = append(parts, fmt.Sprintf("sort %s %s", m.sort, order))
	line := strings.Join(parts, " │ ")
	if m.paused {
		line += " │ " + "PAUSED"
	}
	bar := styleStatusBar.Render(Pad(line, m.width))
	if m.paused {
		// Re-render with the paused marker emphasized.
		bar = styleStatusBar.Render(Pad(strings.Join(parts, " │ ")+" │ ", m.width-7)) + stylePaused.Render("PAUSED ")
	}
	return bar
}

func (m *model) footer(hints string) string {
	return styleFooter.Render(Truncate(" "+hints, m.width))
}
