// Package dnsui is the bubbletea front end for dnsmon: a split view with
// client→resolver transactions on the left and resolver→auth transactions on
// the right, fed by 500ms tracker snapshots — rendering never happens per
// packet. An optional bottom inspector shows the selected transaction's full
// decode and hex, and `w` exports its packets to a pcap.
package dnsui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gopacket/gopacket/layers"

	"github.com/sthorne/network-monitor/internal/capture"
	"github.com/sthorne/network-monitor/internal/dnsmon"
)

// Params wires the UI to the running tracker.
type Params struct {
	Tracker    *dnsmon.Tracker
	Stats      *capture.Stats
	SourceName string
	Live       bool
	// LinkType of the capture source, used when exporting packets to pcap.
	LinkType layers.LinkType
}

// Run starts the TUI and blocks until the user quits.
func Run(p Params) error {
	prog := tea.NewProgram(newModel(p), tea.WithAltScreen())
	_, err := prog.Run()
	return err
}

type (
	tickMsg   time.Time
	snapMsg   struct{ snap dnsmon.Snapshot }
	detailMsg struct {
		detail dnsmon.TxnDetail
		ok     bool
	}
	noticeMsg string
)

type model struct {
	p             Params
	width, height int

	snap     dnsmon.Snapshot
	haveSnap bool
	// Per-side rows, newest query first.
	rows [2][]dnsmon.Row

	focus dnsmon.Side
	// sel is the selected index per pane; selSeq pins it to a transaction
	// across snapshots (0 = follow the newest row).
	sel    [2]int
	selSeq [2]uint64
	scroll [2]int

	inspector  bool
	inspScroll int
	detail     dnsmon.TxnDetail
	haveDetail bool

	showHelp bool
	paused   bool

	notice   string
	noticeAt time.Time

	qps          float64
	lastMsgs     uint64
	lastSnapWall time.Time
}

func newModel(p Params) *model {
	return &model{p: p, width: 80, height: 24}
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(tick(), m.fetchSnapshot())
}

func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *model) fetchSnapshot() tea.Cmd {
	tr := m.p.Tracker
	return func() tea.Msg {
		s, ok := tr.Snapshot()
		if !ok {
			return nil
		}
		return snapMsg{snap: s}
	}
}

// fetchDetail requests the byte-level view of the selected transaction.
func (m *model) fetchDetail() tea.Cmd {
	row, ok := m.selectedRow()
	if !ok {
		return nil
	}
	tr, seq := m.p.Tracker, row.Seq
	return func() tea.Msg {
		d, ok := tr.Detail(seq)
		return detailMsg{detail: d, ok: ok}
	}
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tickMsg:
		cmds := []tea.Cmd{tick()}
		if !m.paused {
			cmds = append(cmds, m.fetchSnapshot())
			if m.inspector {
				cmds = append(cmds, m.fetchDetail())
			}
		}
		return m, tea.Batch(cmds...)

	case snapMsg:
		now := time.Now()
		if m.haveSnap && !m.lastSnapWall.IsZero() {
			if dt := now.Sub(m.lastSnapWall).Seconds(); dt > 0.05 {
				delta := msg.snap.TotalMsgs - m.lastMsgs
				m.qps = float64(delta) / dt
			}
		}
		m.lastMsgs = msg.snap.TotalMsgs
		m.lastSnapWall = now
		m.snap = msg.snap
		m.haveSnap = true
		m.split()
		return m, nil

	case detailMsg:
		if msg.ok {
			m.detail = msg.detail
			m.haveDetail = true
		}
		return m, nil

	case noticeMsg:
		m.notice = string(msg)
		m.noticeAt = time.Now()
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// split partitions snapshot rows by side (newest query first) and re-pins
// each pane's selection.
func (m *model) split() {
	m.rows[0] = m.rows[0][:0]
	m.rows[1] = m.rows[1][:0]
	// Snapshot rows are oldest-first; walk backwards for newest-first panes.
	for i := len(m.snap.Rows) - 1; i >= 0; i-- {
		r := m.snap.Rows[i]
		m.rows[r.Side] = append(m.rows[r.Side], r)
	}
	for side := range m.rows {
		m.repin(side)
	}
}

// repin relocates one pane's pinned selection after rows shifted. selSeq 0
// follows the newest row.
func (m *model) repin(side int) {
	rows := m.rows[side]
	if len(rows) == 0 {
		m.sel[side], m.scroll[side], m.selSeq[side] = 0, 0, 0
		return
	}
	if m.selSeq[side] != 0 {
		for i := range rows {
			if rows[i].Seq == m.selSeq[side] {
				m.sel[side] = i
				m.ensureVisible(side)
				return
			}
		}
		// Pinned transaction evicted: keep the position, re-pin.
	}
	if m.sel[side] >= len(rows) {
		m.sel[side] = len(rows) - 1
	}
	if m.selSeq[side] != 0 {
		m.selSeq[side] = rows[m.sel[side]].Seq
	} else {
		m.sel[side] = 0
	}
	m.ensureVisible(side)
}

func (m *model) selectedRow() (dnsmon.Row, bool) {
	rows := m.rows[m.focus]
	if len(rows) == 0 {
		return dnsmon.Row{}, false
	}
	i := m.sel[m.focus]
	if i < 0 || i >= len(rows) {
		i = 0
	}
	return rows[i], true
}

func (m *model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	if key == "q" || key == "ctrl+c" {
		return m, tea.Quit
	}
	if m.showHelp {
		m.showHelp = false
		return m, nil
	}
	switch key {
	case "?":
		m.showHelp = true
	case "tab", "left", "right", "h", "l":
		m.focus ^= 1
		m.haveDetail = false
		m.inspScroll = 0
		return m, m.fetchDetail()
	case "p":
		m.paused = !m.paused
	case "c":
		tr := m.p.Tracker
		return m, tea.Sequence(
			func() tea.Msg { tr.ClearCompleted(); return nil },
			m.fetchSnapshot(),
		)
	case "enter", "i":
		m.inspector = !m.inspector
		m.inspScroll = 0
		if m.inspector {
			return m, m.fetchDetail()
		}
	case "esc":
		m.inspector = false
	case "w":
		return m, m.saveSelected()
	case "up", "k":
		return m, m.moveSel(-1)
	case "down", "j":
		return m, m.moveSel(1)
	case "pgup":
		return m, m.moveSel(-m.listHeight())
	case "pgdown":
		return m, m.moveSel(m.listHeight())
	case "end":
		return m, m.moveSel(len(m.rows[m.focus]))
	case "home":
		m.selSeq[m.focus] = 0
		m.sel[m.focus] = 0
		m.scroll[m.focus] = 0
		return m, m.fetchDetail()
	case "K", "shift+up":
		m.inspScroll--
		if m.inspScroll < 0 {
			m.inspScroll = 0
		}
	case "J", "shift+down":
		m.inspScroll++
	}
	return m, nil
}

// moveSel moves the focused pane's selection and pins it; moving back to the
// top re-enters follow mode.
func (m *model) moveSel(delta int) tea.Cmd {
	rows := m.rows[m.focus]
	if len(rows) == 0 {
		return nil
	}
	i := m.sel[m.focus] + delta
	if i < 0 {
		i = 0
	}
	if i >= len(rows) {
		i = len(rows) - 1
	}
	m.sel[m.focus] = i
	if i == 0 {
		m.selSeq[m.focus] = 0 // follow newest again
	} else {
		m.selSeq[m.focus] = rows[i].Seq
	}
	m.ensureVisible(int(m.focus))
	m.inspScroll = 0
	if m.inspector {
		return m.fetchDetail()
	}
	return nil
}

func (m *model) ensureVisible(side int) {
	h := m.listHeight()
	if m.sel[side] < m.scroll[side] {
		m.scroll[side] = m.sel[side]
	}
	if m.sel[side] >= m.scroll[side]+h {
		m.scroll[side] = m.sel[side] - h + 1
	}
	if m.scroll[side] < 0 {
		m.scroll[side] = 0
	}
}

// inspectorHeight is the bottom panel's total height (title line included).
func (m *model) inspectorHeight() int {
	if !m.inspector {
		return 0
	}
	h := m.height / 2
	if h < 8 {
		h = 8
	}
	if max := m.height - 8; h > max && max > 0 {
		h = max
	}
	return h
}

func (m *model) listHeight() int {
	h := m.height - 4 - m.inspectorHeight() // status + titles + col header + footer
	if h < 1 {
		h = 1
	}
	return h
}

func (m *model) View() string {
	if m.showHelp {
		return m.viewHelp()
	}
	return m.viewSplit()
}
