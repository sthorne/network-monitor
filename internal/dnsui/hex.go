package dnsui

import (
	"fmt"
	"strings"
)

// hexDump renders b as classic 16-bytes-per-row hex + ASCII lines. At most
// max bytes are dumped; a trailing note reports what was elided.
func hexDump(b []byte, max int) []string {
	n := len(b)
	shown := n
	if max > 0 && shown > max {
		shown = max
	}
	lines := make([]string, 0, shown/16+2)
	for off := 0; off < shown; off += 16 {
		end := off + 16
		if end > shown {
			end = shown
		}
		var hexPart strings.Builder
		var ascii strings.Builder
		for i := off; i < off+16; i++ {
			if i == off+8 {
				hexPart.WriteByte(' ')
			}
			if i < end {
				fmt.Fprintf(&hexPart, "%02x ", b[i])
				c := b[i]
				if c < 0x20 || c > 0x7e {
					c = '.'
				}
				ascii.WriteByte(c)
			} else {
				hexPart.WriteString("   ")
			}
		}
		lines = append(lines, fmt.Sprintf("%04x  %s |%s|", off, hexPart.String(), ascii.String()))
	}
	if shown < n {
		lines = append(lines, fmt.Sprintf("… (%d more bytes)", n-shown))
	}
	return lines
}
