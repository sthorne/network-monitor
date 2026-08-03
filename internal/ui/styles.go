package ui

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/sthorne/network-monitor/internal/flow"
)

var (
	styleStatusBar = lipgloss.NewStyle().
			Foreground(lipgloss.Color("230")).
			Background(lipgloss.Color("24"))
	styleColHeader = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Bold(true)
	styleSelected = lipgloss.NewStyle().
			Background(lipgloss.Color("237")).
			Bold(true)
	styleFooter = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	styleTitle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("81"))
	styleIssue  = lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Bold(true)
	styleDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	styleGood   = lipgloss.NewStyle().Foreground(lipgloss.Color("114"))
	styleWarn   = lipgloss.NewStyle().Foreground(lipgloss.Color("221"))
	stylePaused = lipgloss.NewStyle().Foreground(lipgloss.Color("221")).Bold(true)
	styleBar    = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
)

var stateStyles = map[flow.TCPState]lipgloss.Style{
	flow.StateSynSent: styleWarn,
	flow.StateSynRecv: styleWarn,
	flow.StateEstab:   styleGood,
	flow.StateActive:  styleGood,
	flow.StateFinWait: styleDim,
	flow.StateClosing: styleDim,
	flow.StateClosed:  styleDim,
	flow.StateReset:   styleIssue,
}

func stateStyle(s flow.TCPState) lipgloss.Style {
	if st, ok := stateStyles[s]; ok {
		return st
	}
	return styleDim
}
