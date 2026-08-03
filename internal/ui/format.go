package ui

import (
	"fmt"
	"net/netip"
	"strconv"
	"time"
)

// Bytes renders a byte count in compact human units.
func Bytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatUint(n, 10) + "B"
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(n)/float64(div), "KMGTPE"[exp])
}

// Endpoint renders addr:port (with brackets for IPv6). Port 0 renders the
// bare address (ICMP pseudo-flows).
func Endpoint(addr netip.Addr, port uint16) string {
	if !addr.IsValid() {
		return "-"
	}
	if port == 0 {
		return addr.String()
	}
	if addr.Is6() {
		return "[" + addr.String() + "]:" + strconv.Itoa(int(port))
	}
	return addr.String() + ":" + strconv.Itoa(int(port))
}

// Age renders a duration compactly: 340ms, 12.4s, 3m12s, 2h05m.
func Age(d time.Duration) string {
	switch {
	case d < 0:
		return "0s"
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

// Truncate shortens s to width runes with an ellipsis.
func Truncate(s string, width int) string {
	if width <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	return string(r[:width-1]) + "…"
}

// Pad right-pads or truncates s to exactly width display cells.
func Pad(s string, width int) string {
	s = Truncate(s, width)
	for n := len([]rune(s)); n < width; n++ {
		s += " "
	}
	return s
}

// PadLeft left-pads or truncates s to exactly width cells.
func PadLeft(s string, width int) string {
	s = Truncate(s, width)
	n := len([]rune(s))
	for ; n < width; n++ {
		s = " " + s
	}
	return s
}
