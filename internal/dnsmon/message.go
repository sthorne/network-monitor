// Package dnsmon tracks DNS transactions from a recursive resolver's
// perspective: queries arriving from clients on one side, and the queries the
// resolver itself sends to upstream/authoritative servers on the other. It
// parses DNS messages off the shared capture layer, correlates queries with
// responses by (5-tuple, QID), and classifies each transaction as client-side
// or upstream-side.
package dnsmon

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// Msg is the parsed summary of one DNS message: the full header plus the
// first question. Resource records are not parsed — dnsmon only needs the
// transaction-level view (QID, qname, qtype, rcode, counts).
type Msg struct {
	ID       uint16
	Response bool // QR bit
	Opcode   uint8
	AA, TC   bool
	RD, RA   bool
	RCode    uint8

	QDCount, ANCount, NSCount, ARCount uint16

	// First question (empty when QDCount == 0, which some servers emit on
	// FORMERR responses).
	QName  string
	QType  uint16
	QClass uint16
}

// maxQName bounds the presentation-format name length (RFC 1035 allows 255
// octets on the wire; 253 in presentation format).
const maxQName = 253

// Parse decodes the header and first question of a DNS message. fromTCP
// strips the RFC 1035 two-byte length prefix first. The buffer may be
// truncated after the question section (the capture layer caps payload
// copies); only the header and question are required. ok=false means the
// buffer is not a plausible DNS message.
func Parse(buf []byte, fromTCP bool) (Msg, bool) {
	if fromTCP {
		if len(buf) < 2 {
			return Msg{}, false
		}
		msgLen := int(binary.BigEndian.Uint16(buf))
		if msgLen < 12 {
			return Msg{}, false
		}
		buf = buf[2:]
		if len(buf) > msgLen {
			buf = buf[:msgLen]
		}
	}
	if len(buf) < 12 {
		return Msg{}, false
	}

	flags := binary.BigEndian.Uint16(buf[2:])
	m := Msg{
		ID:       binary.BigEndian.Uint16(buf[0:]),
		Response: flags&0x8000 != 0,
		Opcode:   uint8(flags >> 11 & 0x0f),
		AA:       flags&0x0400 != 0,
		TC:       flags&0x0200 != 0,
		RD:       flags&0x0100 != 0,
		RA:       flags&0x0080 != 0,
		RCode:    uint8(flags & 0x0f),
		QDCount:  binary.BigEndian.Uint16(buf[4:]),
		ANCount:  binary.BigEndian.Uint16(buf[6:]),
		NSCount:  binary.BigEndian.Uint16(buf[8:]),
		ARCount:  binary.BigEndian.Uint16(buf[10:]),
	}
	// Opcodes above UPDATE(5) and implausibly large question counts mark
	// non-DNS traffic that happens to cross port 53.
	if m.Opcode > 5 || m.QDCount > 8 {
		return Msg{}, false
	}
	if m.QDCount == 0 {
		return m, true
	}

	name, off, ok := parseName(buf, 12)
	if !ok || len(buf) < off+4 {
		return Msg{}, false
	}
	m.QName = name
	m.QType = binary.BigEndian.Uint16(buf[off:])
	m.QClass = binary.BigEndian.Uint16(buf[off+2:])
	return m, true
}

// parseName decodes a wire-format domain name at off, following compression
// pointers (bounded, so malicious pointer loops terminate). It returns the
// lower-cased presentation-format name and the offset just past the name at
// its original position.
func parseName(buf []byte, off int) (string, int, bool) {
	var out []byte
	end := -1 // offset after the name at the original location
	jumps := 0
	for {
		if off >= len(buf) {
			return "", 0, false
		}
		b := buf[off]
		switch {
		case b == 0:
			if end < 0 {
				end = off + 1
			}
			return string(out), end, true
		case b&0xc0 == 0xc0: // compression pointer
			if off+1 >= len(buf) {
				return "", 0, false
			}
			if end < 0 {
				end = off + 2
			}
			if jumps++; jumps > 16 {
				return "", 0, false
			}
			off = int(b&0x3f)<<8 | int(buf[off+1])
		case b&0xc0 != 0: // reserved label types
			return "", 0, false
		default:
			n := int(b)
			off++
			if off+n > len(buf) {
				return "", 0, false
			}
			if len(out) > 0 {
				out = append(out, '.')
			}
			for _, c := range buf[off : off+n] {
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				if c < 0x21 || c > 0x7e || c == '.' {
					c = '?'
				}
				out = append(out, c)
			}
			if len(out) > maxQName {
				return "", 0, false
			}
			off += n
		}
	}
}

var typeNames = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO",
	15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 25: "KEY", 28: "AAAA",
	29: "LOC", 33: "SRV", 35: "NAPTR", 36: "KX", 37: "CERT", 39: "DNAME",
	41: "OPT", 43: "DS", 44: "SSHFP", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY",
	50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 59: "CDS", 60: "CDNSKEY",
	64: "SVCB", 65: "HTTPS", 99: "SPF", 108: "EUI48", 109: "EUI64",
	249: "TKEY", 250: "TSIG", 251: "IXFR", 252: "AXFR", 255: "ANY", 257: "CAA",
}

// TypeName renders a query type mnemonic ("A", "AAAA", ...; "TYPE1234" for
// unknown codes).
func TypeName(t uint16) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return "TYPE" + strconv.Itoa(int(t))
}

var rcodeNames = [...]string{
	"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
	"YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE",
}

// RCodeName renders a response code mnemonic ("NOERROR", "NXDOMAIN", ...).
func RCodeName(rc uint8) string {
	if int(rc) < len(rcodeNames) {
		return rcodeNames[rc]
	}
	return "RCODE" + strconv.Itoa(int(rc))
}

// EqualName compares two presentation-format names case-insensitively (Parse
// already lower-cases, but explicit --resolver input may not be).
func EqualName(a, b string) bool { return strings.EqualFold(a, b) }
