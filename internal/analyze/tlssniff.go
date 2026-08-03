package analyze

import "encoding/binary"

// parseClientHello extracts SNI and the first ALPN protocol from a TLS
// ClientHello record. The input may be truncated (the sniffer only keeps the
// first few hundred bytes); parsing stops cleanly at the end of the buffer.
// ok reports that the buffer is structurally a ClientHello, even when the
// extensions were cut off before SNI/ALPN were found.
func parseClientHello(b []byte) (sni, alpn string, ok bool) {
	// TLS record header: type(1)=0x16 version(2)=0x03xx length(2).
	if len(b) < 6 || b[0] != 0x16 || b[1] != 0x03 {
		return "", "", false
	}
	// Handshake header: type(1)=0x01 length(3).
	hs := b[5:]
	if len(hs) < 4 || hs[0] != 0x01 {
		return "", "", false
	}
	p := hs[4:]

	// client_version(2) random(32)
	if len(p) < 34 {
		return "", "", true
	}
	p = p[34:]

	// session_id
	if len(p) < 1 {
		return "", "", true
	}
	n := int(p[0])
	p = p[1:]
	if len(p) < n {
		return "", "", true
	}
	p = p[n:]

	// cipher_suites
	if len(p) < 2 {
		return "", "", true
	}
	n = int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) < n {
		return "", "", true
	}
	p = p[n:]

	// compression_methods
	if len(p) < 1 {
		return "", "", true
	}
	n = int(p[0])
	p = p[1:]
	if len(p) < n {
		return "", "", true
	}
	p = p[n:]

	// extensions
	if len(p) < 2 {
		return "", "", true
	}
	extLen := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if extLen < len(p) {
		p = p[:extLen]
	}
	for len(p) >= 4 {
		extType := binary.BigEndian.Uint16(p)
		n = int(binary.BigEndian.Uint16(p[2:]))
		p = p[4:]
		if len(p) < n {
			return sni, alpn, true
		}
		body := p[:n]
		p = p[n:]
		switch extType {
		case 0: // server_name
			if s := parseSNI(body); s != "" {
				sni = s
			}
		case 16: // ALPN
			if a := parseALPN(body); a != "" {
				alpn = a
			}
		}
		if sni != "" && alpn != "" {
			break
		}
	}
	return sni, alpn, true
}

func parseSNI(b []byte) string {
	// server_name_list length(2), then entries: type(1) length(2) name.
	if len(b) < 2 {
		return ""
	}
	b = b[2:]
	for len(b) >= 3 {
		nameType := b[0]
		n := int(binary.BigEndian.Uint16(b[1:]))
		b = b[3:]
		if len(b) < n {
			return ""
		}
		if nameType == 0 && validHostname(b[:n]) {
			return string(b[:n])
		}
		b = b[n:]
	}
	return ""
}

func parseALPN(b []byte) string {
	// protocol_name_list length(2), then entries: length(1) name.
	if len(b) < 2 {
		return ""
	}
	b = b[2:]
	if len(b) < 1 {
		return ""
	}
	n := int(b[0])
	b = b[1:]
	if len(b) < n || n == 0 {
		return ""
	}
	return string(b[:n])
}

func validHostname(b []byte) bool {
	if len(b) == 0 || len(b) > 253 {
		return false
	}
	for _, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}
