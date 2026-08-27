package dnsui

import (
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/sthorne/network-monitor/internal/dnsmon"
)

// saveSelected exports the selected transaction's packets to a file in the
// working directory: a pcap of the captured query/response frames when raw
// frames were kept, otherwise the raw DNS message bytes.
func (m *model) saveSelected() tea.Cmd {
	row, ok := m.selectedRow()
	if !ok {
		return func() tea.Msg { return noticeMsg("nothing selected") }
	}
	tr, link, seq := m.p.Tracker, m.p.LinkType, row.Seq
	return func() tea.Msg {
		d, ok := tr.Detail(seq)
		if !ok {
			return noticeMsg("transaction no longer available")
		}
		name, err := writeTxnFile(&d, link)
		if err != nil {
			return noticeMsg("save failed: " + err.Error())
		}
		return noticeMsg("saved " + name)
	}
}

// writeTxnFile writes one transaction to disk and returns the filename(s).
func writeTxnFile(d *dnsmon.TxnDetail, link layers.LinkType) (string, error) {
	base := fmt.Sprintf("dnsmon-%s-qid%d-%s",
		sanitizeName(d.QName), d.QID, d.QueryTS.Format("20060102-150405"))

	if len(d.QueryFrame) > 0 || len(d.RespFrame) > 0 {
		name := base + ".pcap"
		f, err := os.Create(name)
		if err != nil {
			return "", err
		}
		defer f.Close()
		w := pcapgo.NewWriter(f)
		if err := w.WriteFileHeader(65535, link); err != nil {
			return "", err
		}
		write := func(frame []byte, wireLen int, ts time.Time) error {
			if len(frame) == 0 {
				return nil
			}
			if wireLen < len(frame) {
				wireLen = len(frame)
			}
			return w.WritePacket(gopacket.CaptureInfo{
				Timestamp: ts, CaptureLength: len(frame), Length: wireLen,
			}, frame)
		}
		if err := write(d.QueryFrame, d.QueryWireLen, d.QueryTS); err != nil {
			return "", err
		}
		if err := write(d.RespFrame, d.RespWireLen, d.RespTS); err != nil {
			return "", err
		}
		return name, nil
	}

	// No raw frames (e.g. tracker fed without KeepRaw): fall back to the DNS
	// message bytes.
	var names []string
	if len(d.QueryMsg) > 0 {
		n := base + "-query.bin"
		if err := os.WriteFile(n, d.QueryMsg, 0o644); err != nil {
			return "", err
		}
		names = append(names, n)
	}
	if len(d.RespMsg) > 0 {
		n := base + "-response.bin"
		if err := os.WriteFile(n, d.RespMsg, 0o644); err != nil {
			return "", err
		}
		names = append(names, n)
	}
	if len(names) == 0 {
		return "", fmt.Errorf("no packet bytes retained for this transaction")
	}
	return strings.Join(names, ", "), nil
}

// sanitizeName makes a qname safe for a filename.
func sanitizeName(qname string) string {
	if qname == "" {
		return "txn"
	}
	var b strings.Builder
	for _, c := range qname {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-':
			b.WriteRune(c)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
