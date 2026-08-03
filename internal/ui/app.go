// Package ui is the bubbletea front end: a flow-list timeline, a per-flow
// detail screen, and a top-clients screen, all fed by 500ms tracker
// snapshots — rendering never happens per packet.
package ui

import (
	"sort"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sthorne/network-monitor/internal/capture"
	"github.com/sthorne/network-monitor/internal/flow"
)

// Params wires the UI to the running tracker.
type Params struct {
	Tracker    *flow.Tracker
	Stats      *capture.Stats
	SourceName string
	Live       bool
}

// Run starts the TUI and blocks until the user quits.
func Run(p Params) error {
	prog := tea.NewProgram(newModel(p), tea.WithAltScreen())
	_, err := prog.Run()
	return err
}

type screen int

const (
	screenFlows screen = iota
	screenDetail
	screenTop
)

type sortMode int

const (
	sortActivity sortMode = iota
	sortBytes
	sortDuration
	sortFirstSeen
	sortState
	sortModeCount
)

func (s sortMode) String() string {
	switch s {
	case sortActivity:
		return "activity"
	case sortBytes:
		return "bytes"
	case sortDuration:
		return "duration"
	case sortFirstSeen:
		return "first-seen"
	case sortState:
		return "state"
	}
	return "?"
}

type (
	tickMsg   time.Time
	snapMsg   struct{ snap flow.Snapshot }
	detailMsg struct {
		detail flow.FlowDetail
		ok     bool
	}
)

type model struct {
	p             Params
	width, height int

	snap     flow.Snapshot
	haveSnap bool
	rows     []flow.FlowRow

	detail     flow.FlowDetail
	haveDetail bool

	scr      screen
	showHelp bool
	paused   bool
	sort     sortMode
	sortAsc  bool

	selKey  flow.FlowKey
	haveSel bool
	selIdx  int
	scroll  int

	detailScroll int

	pps          float64
	lastPkts     uint64
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

func (m *model) fetchDetail() tea.Cmd {
	tr, key := m.p.Tracker, m.selKey
	return func() tea.Msg {
		d, ok := tr.Detail(key)
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
			if m.scr == screenDetail && m.haveSel {
				cmds = append(cmds, m.fetchDetail())
			}
		}
		return m, tea.Batch(cmds...)

	case snapMsg:
		now := time.Now()
		if m.haveSnap && !m.lastSnapWall.IsZero() {
			if dt := now.Sub(m.lastSnapWall).Seconds(); dt > 0.05 {
				delta := msg.snap.TotalPkts - m.lastPkts
				m.pps = float64(delta) / dt
			}
		}
		m.lastPkts = msg.snap.TotalPkts
		m.lastSnapWall = now
		m.snap = msg.snap
		m.haveSnap = true
		m.resort()
		return m, nil

	case detailMsg:
		if msg.ok {
			m.detail = msg.detail
			m.haveDetail = true
		}
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
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
		return m, nil
	case "t":
		if m.scr == screenTop {
			m.scr = screenFlows
		} else {
			m.scr = screenTop
		}
		return m, nil
	case "p":
		m.paused = !m.paused
		return m, nil
	case "c":
		tr := m.p.Tracker
		return m, tea.Sequence(
			func() tea.Msg { tr.ClearClosed(); return nil },
			m.fetchSnapshot(),
		)
	}

	switch m.scr {
	case screenFlows:
		return m.handleFlowsKey(key)
	case screenDetail:
		return m.handleDetailKey(key)
	case screenTop:
		if key == "esc" {
			m.scr = screenFlows
		}
		return m, nil
	}
	return m, nil
}

func (m *model) handleFlowsKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		m.moveSel(-1)
	case "down", "j":
		m.moveSel(1)
	case "pgup":
		m.moveSel(-m.listHeight())
	case "pgdown":
		m.moveSel(m.listHeight())
	case "home":
		m.moveSel(-len(m.rows))
	case "end":
		m.moveSel(len(m.rows))
	case "enter":
		if m.haveSel {
			m.scr = screenDetail
			m.detailScroll = 0
			m.haveDetail = false
			return m, m.fetchDetail()
		}
	case "s":
		m.sort = (m.sort + 1) % sortModeCount
		m.resort()
	case "o":
		m.sortAsc = !m.sortAsc
		m.resort()
	case "esc":
		// nothing
	}
	return m, nil
}

func (m *model) handleDetailKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "enter":
		m.scr = screenFlows
	case "up", "k":
		m.detailScroll--
	case "down", "j":
		m.detailScroll++
	case "pgup":
		m.detailScroll -= m.bodyHeight()
	case "pgdown":
		m.detailScroll += m.bodyHeight()
	case "home":
		m.detailScroll = 0
	}
	if m.detailScroll < 0 {
		m.detailScroll = 0
	}
	return m, nil
}

func (m *model) moveSel(delta int) {
	if len(m.rows) == 0 {
		m.haveSel = false
		return
	}
	idx := m.selIdx + delta
	if idx < 0 {
		idx = 0
	}
	if idx >= len(m.rows) {
		idx = len(m.rows) - 1
	}
	m.selIdx = idx
	m.selKey = m.rows[idx].Key
	m.haveSel = true
	m.ensureVisible()
}

// resort re-sorts rows after a new snapshot and pins the selection to its
// FlowKey so rows shifting underneath don't move the cursor's target.
func (m *model) resort() {
	m.rows = append(m.rows[:0], m.snap.Flows...)
	less := m.lessFunc()
	sort.SliceStable(m.rows, func(i, j int) bool {
		if m.sortAsc {
			return less(j, i)
		}
		return less(i, j)
	})

	if len(m.rows) == 0 {
		m.haveSel = false
		m.selIdx, m.scroll = 0, 0
		return
	}
	if m.haveSel {
		for i := range m.rows {
			if m.rows[i].Key == m.selKey {
				m.selIdx = i
				m.ensureVisible()
				return
			}
		}
	}
	// Selection vanished (evicted) or nothing selected yet: clamp index.
	if m.selIdx >= len(m.rows) {
		m.selIdx = len(m.rows) - 1
	}
	if m.selIdx < 0 {
		m.selIdx = 0
	}
	m.selKey = m.rows[m.selIdx].Key
	m.haveSel = true
	m.ensureVisible()
}

// lessFunc returns the "greater first" comparison for the current sort mode
// (descending order is the natural reading for every mode).
func (m *model) lessFunc() func(i, j int) bool {
	r := m.rows
	switch m.sort {
	case sortBytes:
		return func(i, j int) bool { return r[i].BytesOut+r[i].BytesIn > r[j].BytesOut+r[j].BytesIn }
	case sortDuration:
		return func(i, j int) bool {
			return r[i].LastSeen.Sub(r[i].FirstSeen) > r[j].LastSeen.Sub(r[j].FirstSeen)
		}
	case sortFirstSeen:
		return func(i, j int) bool { return r[i].FirstSeen.After(r[j].FirstSeen) }
	case sortState:
		return func(i, j int) bool {
			if r[i].State != r[j].State {
				return r[i].State < r[j].State
			}
			return r[i].LastSeen.After(r[j].LastSeen)
		}
	default: // sortActivity
		return func(i, j int) bool { return r[i].LastSeen.After(r[j].LastSeen) }
	}
}

func (m *model) listHeight() int {
	h := m.height - 3 // status bar + column header + footer
	if h < 1 {
		h = 1
	}
	return h
}

func (m *model) bodyHeight() int {
	h := m.height - 2 // status bar + footer
	if h < 1 {
		h = 1
	}
	return h
}

func (m *model) ensureVisible() {
	h := m.listHeight()
	if m.selIdx < m.scroll {
		m.scroll = m.selIdx
	}
	if m.selIdx >= m.scroll+h {
		m.scroll = m.selIdx - h + 1
	}
	if m.scroll < 0 {
		m.scroll = 0
	}
}

func (m *model) View() string {
	if m.showHelp {
		return m.viewHelp()
	}
	switch m.scr {
	case screenDetail:
		return m.viewDetail()
	case screenTop:
		return m.viewTopTalkers()
	default:
		return m.viewFlowList()
	}
}
