// Package dnsui is the bubbletea front end for dnsmon: a split view with
// client→resolver transactions on the left and resolver→auth transactions on
// the right, fed by 500ms tracker snapshots — rendering never happens per
// packet.
package dnsui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sthorne/network-monitor/internal/capture"
	"github.com/sthorne/network-monitor/internal/dnsmon"
)

// Params wires the UI to the running tracker.
type Params struct {
	Tracker    *dnsmon.Tracker
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

type (
	tickMsg time.Time
	snapMsg struct{ snap dnsmon.Snapshot }
)

type model struct {
	p             Params
	width, height int

	snap     dnsmon.Snapshot
	haveSnap bool
	// Per-side rows, newest query first.
	rows [2][]dnsmon.Row

	focus    dnsmon.Side
	scroll   [2]int
	showHelp bool
	paused   bool

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

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tickMsg:
		cmds := []tea.Cmd{tick()}
		if !m.paused {
			cmds = append(cmds, m.fetchSnapshot())
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

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// split partitions snapshot rows by side, newest query first.
func (m *model) split() {
	m.rows[0] = m.rows[0][:0]
	m.rows[1] = m.rows[1][:0]
	// Snapshot rows are oldest-first; walk backwards for newest-first panes.
	for i := len(m.snap.Rows) - 1; i >= 0; i-- {
		r := m.snap.Rows[i]
		m.rows[r.Side] = append(m.rows[r.Side], r)
	}
	for side := range m.scroll {
		if max := len(m.rows[side]) - 1; m.scroll[side] > max {
			if max < 0 {
				max = 0
			}
			m.scroll[side] = max
		}
	}
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
	case "p":
		m.paused = !m.paused
	case "c":
		tr := m.p.Tracker
		return m, tea.Sequence(
			func() tea.Msg { tr.ClearCompleted(); return nil },
			m.fetchSnapshot(),
		)
	case "up", "k":
		m.scrollBy(-1)
	case "down", "j":
		m.scrollBy(1)
	case "pgup":
		m.scrollBy(-m.listHeight())
	case "pgdown":
		m.scrollBy(m.listHeight())
	case "home":
		m.scroll[m.focus] = 0
	}
	return m, nil
}

// scrollBy moves the focused pane. Offset 0 pins the pane to the newest
// transactions (follow mode).
func (m *model) scrollBy(delta int) {
	s := m.scroll[m.focus] + delta
	if s < 0 {
		s = 0
	}
	if max := len(m.rows[m.focus]) - 1; s > max {
		if max < 0 {
			max = 0
		}
		s = max
	}
	m.scroll[m.focus] = s
}

func (m *model) listHeight() int {
	h := m.height - 4 // status bar + pane titles + column header + footer
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
