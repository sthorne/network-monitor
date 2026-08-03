package analyze

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/sthorne/network-monitor/internal/capture"
)

// Result is an application-protocol identification for a flow.
type Result struct {
	Name     string // e.g. "TLS", "HTTP", "https?" (trailing ? = port-only guess)
	Detail   string // SNI + ALPN, request line, DNS qname, ...
	FromPort bool
}

func (r Result) Label() string {
	if r.Name == "" {
		return "-"
	}
	if r.Detail != "" {
		return r.Name + " (" + r.Detail + ")"
	}
	return r.Name
}

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("HEAD "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
}

// Sniff inspects one direction's accumulated leading payload and attempts to
// identify the application protocol. decided=false means "keep feeding me".
func Sniff(transport capture.Proto, sport, dport uint16, buf []byte) (Result, bool) {
	if len(buf) == 0 {
		return Result{}, false
	}

	// TLS ClientHello (also matches other handshake records → plain "TLS").
	if transport == capture.ProtoTCP && len(buf) >= 6 && buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x04 {
		if buf[5] == 0x01 {
			sni, alpn, ok := parseClientHello(buf)
			if ok {
				detail := sni
				if alpn != "" {
					if detail != "" {
						detail += ", "
					}
					detail += alpn
				}
				return Result{Name: "TLS", Detail: detail}, true
			}
		}
		return Result{Name: "TLS"}, true
	}

	if transport == capture.ProtoTCP {
		for _, m := range httpMethods {
			if bytes.HasPrefix(buf, m) {
				return Result{Name: "HTTP", Detail: requestLine(buf)}, true
			}
		}
		if bytes.HasPrefix(buf, []byte("HTTP/1.")) {
			return Result{Name: "HTTP"}, true
		}
		if bytes.HasPrefix(buf, []byte("SSH-")) {
			return Result{Name: "SSH", Detail: requestLine(buf)}, true
		}
	}

	if sport == 53 || dport == 53 {
		if name, ok := sniffDNS(transport, buf); ok {
			return Result{Name: "DNS", Detail: name}, true
		}
	}

	// QUIC long-header packet (version field must be plausible).
	if transport == capture.ProtoUDP && len(buf) >= 5 && buf[0]&0x80 != 0 {
		v := binary.BigEndian.Uint32(buf[1:])
		if v == 1 || v == 2 || v&0xffffff00 == 0xff000000 || v&0x0f0f0f0f == 0x0a0a0a0a {
			return Result{Name: "QUIC"}, true
		}
	}

	return Result{}, false
}

// requestLine returns the first line of a text protocol, bounded and cleaned.
func requestLine(buf []byte) string {
	n := bytes.IndexAny(buf, "\r\n")
	if n < 0 {
		n = len(buf)
	}
	if n > 80 {
		n = 80
	}
	line := buf[:n]
	for _, c := range line {
		if c < 0x20 || c > 0x7e {
			return ""
		}
	}
	return string(line)
}

// sniffDNS validates a DNS message header and extracts the first question
// name. TCP DNS carries a 2-byte length prefix.
func sniffDNS(transport capture.Proto, buf []byte) (string, bool) {
	if transport == capture.ProtoTCP {
		if len(buf) < 2 {
			return "", false
		}
		buf = buf[2:]
	}
	if len(buf) < 12 {
		return "", false
	}
	opcode := (buf[2] >> 3) & 0x0f
	qd := binary.BigEndian.Uint16(buf[4:])
	if opcode > 5 || qd == 0 || qd > 8 {
		return "", false
	}
	return dnsName(buf[12:]), true
}

func dnsName(b []byte) string {
	var out []byte
	for len(b) > 0 {
		n := int(b[0])
		if n == 0 || n > 63 {
			break
		}
		b = b[1:]
		if len(b) < n {
			break
		}
		if len(out) > 0 {
			out = append(out, '.')
		}
		for _, c := range b[:n] {
			if c < 0x21 || c > 0x7e {
				return ""
			}
		}
		out = append(out, b[:n]...)
		b = b[n:]
		if len(out) > 200 {
			break
		}
	}
	return string(out)
}

// wellKnownPorts maps ports to protocol guesses used when payload sniffing
// was inconclusive. Labels carry a "?" suffix to mark port-only inference.
var wellKnownPorts = map[uint16]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3",
	123: "ntp", 143: "imap", 161: "snmp", 179: "bgp", 389: "ldap",
	443: "https", 445: "smb", 465: "smtps", 514: "syslog", 587: "smtp",
	636: "ldaps", 853: "dot", 993: "imaps", 995: "pop3s", 1433: "mssql",
	3306: "mysql", 3389: "rdp", 5432: "postgres", 5671: "amqps", 5672: "amqp",
	6379: "redis", 8080: "http-alt", 8443: "https-alt", 9092: "kafka",
	27017: "mongodb",
}

// PortFallback guesses a protocol from the well-known-port table.
func PortFallback(transport capture.Proto, portA, portB uint16) Result {
	for _, p := range []uint16{portA, portB} {
		if name, ok := wellKnownPorts[p]; ok {
			return Result{Name: name + "?", FromPort: true}
		}
	}
	if transport == capture.ProtoICMPv4 || transport == capture.ProtoICMPv6 {
		return Result{Name: "icmp"}
	}
	return Result{}
}

// ICMPLabel describes an ICMP type/code pair for display.
func ICMPLabel(proto capture.Proto, typ, code uint8) string {
	if proto == capture.ProtoICMPv4 {
		switch typ {
		case 0:
			return "echo reply"
		case 8:
			return "echo request"
		case 3:
			return fmt.Sprintf("unreachable (code %d)", code)
		case 11:
			return "time exceeded"
		}
	} else {
		switch typ {
		case 128:
			return "echo request"
		case 129:
			return "echo reply"
		case 1:
			return fmt.Sprintf("unreachable (code %d)", code)
		case 3:
			return "time exceeded"
		}
	}
	return fmt.Sprintf("type %d code %d", typ, code)
}
