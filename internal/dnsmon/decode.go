package dnsmon

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Question is one entry of the question section.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// RR is one resource record, with its rdata rendered to text for display.
type RR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string // presentation-format rdata, or a hex preview for unknown types
}

// EDNS is the OPT pseudo-record summary from the additional section.
type EDNS struct {
	Present    bool
	Version    uint8
	UDPSize    uint16
	DO         bool
	ExtendedRC uint8 // upper bits of the extended rcode
}

// MsgDetail is the full decode of a DNS message for the inspector view.
type MsgDetail struct {
	Msg
	Questions  []Question
	Answers    []RR
	Authority  []RR
	Additional []RR // OPT excluded (summarized in EDNS)
	EDNS       EDNS
	Truncated  bool // decode stopped early (malformed tail or record cap)
}

// maxDecodeRRs bounds how many records are walked per message.
const maxDecodeRRs = 64

// DecodeDetail parses a complete DNS message: header, all questions, and all
// resource records with rendered rdata. It is lenient past the header — a
// malformed or truncated tail yields whatever decoded cleanly, with
// Truncated set — since the inspector should show as much as possible.
func DecodeDetail(buf []byte, fromTCP bool) (MsgDetail, bool) {
	msg, ok := Parse(buf, fromTCP)
	if !ok {
		return MsgDetail{}, false
	}
	if fromTCP {
		msgLen := int(binary.BigEndian.Uint16(buf))
		buf = buf[2:]
		if len(buf) > msgLen {
			buf = buf[:msgLen]
		}
	}

	d := MsgDetail{Msg: msg}
	off := 12
	for i := 0; i < int(msg.QDCount); i++ {
		name, next, ok := parseName(buf, off)
		if !ok || len(buf) < next+4 {
			d.Truncated = true
			return d, true
		}
		d.Questions = append(d.Questions, Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(buf[next:]),
			Class: binary.BigEndian.Uint16(buf[next+2:]),
		})
		off = next + 4
	}

	sections := []struct {
		count uint16
		out   *[]RR
	}{
		{msg.ANCount, &d.Answers},
		{msg.NSCount, &d.Authority},
		{msg.ARCount, &d.Additional},
	}
	total := 0
	for _, sec := range sections {
		for i := 0; i < int(sec.count); i++ {
			if total++; total > maxDecodeRRs {
				d.Truncated = true
				return d, true
			}
			rr, isOpt, next, ok := parseRR(buf, off, &d.EDNS)
			if !ok {
				d.Truncated = true
				return d, true
			}
			if !isOpt {
				*sec.out = append(*sec.out, rr)
			}
			off = next
		}
	}
	return d, true
}

// parseRR decodes one resource record at off. OPT records are folded into
// edns instead of being returned.
func parseRR(buf []byte, off int, edns *EDNS) (RR, bool, int, bool) {
	name, next, ok := parseName(buf, off)
	if !ok || len(buf) < next+10 {
		return RR{}, false, 0, false
	}
	typ := binary.BigEndian.Uint16(buf[next:])
	class := binary.BigEndian.Uint16(buf[next+2:])
	ttl := binary.BigEndian.Uint32(buf[next+4:])
	rdlen := int(binary.BigEndian.Uint16(buf[next+8:]))
	rdStart := next + 10
	if len(buf) < rdStart+rdlen {
		return RR{}, false, 0, false
	}

	if typ == 41 { // OPT: EDNS pseudo-record
		edns.Present = true
		edns.UDPSize = class
		edns.ExtendedRC = uint8(ttl >> 24)
		edns.Version = uint8(ttl >> 16)
		edns.DO = ttl&0x8000 != 0
		return RR{}, true, rdStart + rdlen, true
	}

	rr := RR{
		Name: name, Type: typ, Class: class, TTL: ttl,
		Data: renderRData(buf, rdStart, rdlen, typ),
	}
	return rr, false, rdStart + rdlen, true
}

// renderRData formats rdata for the common types; anything else gets an
// RFC 3597-style hex preview. rdata lives at buf[off:off+rdlen] — the full
// buffer is passed so compressed names inside rdata resolve.
func renderRData(buf []byte, off, rdlen int, typ uint16) string {
	rd := buf[off : off+rdlen]
	switch typ {
	case 1: // A
		if a, ok := netip.AddrFromSlice(rd); ok {
			return a.String()
		}
	case 28: // AAAA
		if a, ok := netip.AddrFromSlice(rd); ok {
			return a.String()
		}
	case 2, 5, 12, 39: // NS, CNAME, PTR, DNAME
		if n, _, ok := parseName(buf, off); ok {
			return n + "."
		}
	case 15: // MX
		if rdlen >= 3 {
			if n, _, ok := parseName(buf, off+2); ok {
				return fmt.Sprintf("%d %s.", binary.BigEndian.Uint16(rd), n)
			}
		}
	case 16, 99: // TXT, SPF
		var parts []string
		for i := 0; i < len(rd); {
			n := int(rd[i])
			i++
			if i+n > len(rd) {
				break
			}
			parts = append(parts, strconv.Quote(string(rd[i:i+n])))
			i += n
		}
		if len(parts) > 0 {
			return strings.Join(parts, " ")
		}
	case 6: // SOA
		mname, next, ok := parseName(buf, off)
		if ok {
			rname, next2, ok2 := parseName(buf, next)
			if ok2 && len(buf) >= next2+20 {
				v := buf[next2:]
				return fmt.Sprintf("%s. %s. %d %d %d %d %d",
					mname, rname,
					binary.BigEndian.Uint32(v), binary.BigEndian.Uint32(v[4:]),
					binary.BigEndian.Uint32(v[8:]), binary.BigEndian.Uint32(v[12:]),
					binary.BigEndian.Uint32(v[16:]))
			}
		}
	case 33: // SRV
		if rdlen >= 7 {
			if n, _, ok := parseName(buf, off+6); ok {
				return fmt.Sprintf("%d %d %d %s.",
					binary.BigEndian.Uint16(rd), binary.BigEndian.Uint16(rd[2:]),
					binary.BigEndian.Uint16(rd[4:]), n)
			}
		}
	case 257: // CAA
		if rdlen >= 2 {
			tagLen := int(rd[1])
			if 2+tagLen <= len(rd) {
				return fmt.Sprintf("%d %s %q", rd[0], rd[2:2+tagLen], rd[2+tagLen:])
			}
		}
	}
	preview := rd
	if len(preview) > 24 {
		preview = preview[:24]
	}
	s := fmt.Sprintf("\\# %d %s", rdlen, hex.EncodeToString(preview))
	if len(rd) > 24 {
		s += "…"
	}
	return s
}

// FlagString renders the header flag mnemonics ("qr rd ra", dig-style).
func (m *Msg) FlagString() string {
	var f []string
	if m.Response {
		f = append(f, "qr")
	}
	if m.AA {
		f = append(f, "aa")
	}
	if m.TC {
		f = append(f, "tc")
	}
	if m.RD {
		f = append(f, "rd")
	}
	if m.RA {
		f = append(f, "ra")
	}
	if len(f) == 0 {
		return "-"
	}
	return strings.Join(f, " ")
}

var opcodeNames = [...]string{"QUERY", "IQUERY", "STATUS", "OPCODE3", "NOTIFY", "UPDATE"}

// OpcodeName renders the opcode mnemonic.
func OpcodeName(op uint8) string {
	if int(op) < len(opcodeNames) {
		return opcodeNames[op]
	}
	return "OPCODE" + strconv.Itoa(int(op))
}

var classNames = map[uint16]string{1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}

// ClassName renders the class mnemonic.
func ClassName(c uint16) string {
	if n, ok := classNames[c]; ok {
		return n
	}
	return "CLASS" + strconv.Itoa(int(c))
}
