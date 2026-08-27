// Command gendnspcap writes a scripted capture of a recursive resolver's DNS
// traffic — clients querying the resolver, the resolver recursing to
// authoritative servers, cache hits, an NXDOMAIN, a SERVFAIL, and an upstream
// timeout — for demoing dnsmon --read without live traffic.
package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

var (
	resolver = net.IP{192, 0, 2, 53}
	clientA  = net.IP{10, 1, 0, 11}
	clientB  = net.IP{10, 1, 0, 12}
	clientC  = net.IP{10, 1, 0, 13}
	rootSrv  = net.IP{198, 41, 0, 4}    // a.root-servers.net
	tldSrv   = net.IP{192, 5, 6, 30}    // a.gtld-servers.net
	authSrv  = net.IP{199, 43, 135, 53} // example.com auth
)

type builder struct {
	w  *pcapgo.Writer
	ts time.Time
}

func (b *builder) step(d time.Duration) { b.ts = b.ts.Add(d) }

func (b *builder) udp(src, dst net.IP, sp, dp layers.UDPPort, payload []byte) {
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: src, DstIP: dst}
	udp := &layers.UDP{SrcPort: sp, DstPort: dp}
	udp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		log.Fatal(err)
	}
	data := buf.Bytes()
	ci := gopacket.CaptureInfo{Timestamp: b.ts, CaptureLength: len(data), Length: len(data)}
	if err := b.w.WritePacket(ci, data); err != nil {
		log.Fatal(err)
	}
	b.step(2 * time.Millisecond)
}

// query builds a DNS query message.
func query(id uint16, name string, qtype uint16) []byte {
	msg := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	return append(msg, question(name, qtype)...)
}

// response builds a DNS response echoing the question, with rcode and an
// answer count (answer records themselves are not needed by dnsmon).
func response(id uint16, name string, qtype uint16, rcode uint8, answers uint16) []byte {
	msg := []byte{byte(id >> 8), byte(id), 0x81, 0x80 | rcode, 0, 1, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(msg[6:], answers)
	return append(msg, question(name, qtype)...)
}

func question(name string, qtype uint16) []byte {
	var q []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			q = append(q, byte(i-start))
			q = append(q, name[start:i]...)
			start = i + 1
		}
	}
	q = append(q, 0)
	q = append(q, byte(qtype>>8), byte(qtype), 0, 1)
	return q
}

const (
	typeA    = 1
	typeNS   = 2
	typeMX   = 15
	typeTXT  = 16
	typeAAAA = 28
)

func main() {
	out := flag.String("o", "dns-demo.pcap", "output file")
	flag.Parse()

	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		log.Fatal(err)
	}
	b := &builder{w: w, ts: time.Now().Add(-30 * time.Second)}

	// --- Full recursion: client A asks for www.example.com A; the resolver
	// walks root → TLD → auth, then answers the client.
	b.udp(clientA, resolver, 54001, 53, query(0x1111, "www.example.com", typeA))
	b.udp(resolver, rootSrv, 40001, 53, query(0x2001, "www.example.com", typeA))
	b.udp(rootSrv, resolver, 53, 40001, response(0x2001, "www.example.com", typeA, 0, 0)) // referral
	b.udp(resolver, tldSrv, 40002, 53, query(0x2002, "www.example.com", typeA))
	b.udp(tldSrv, resolver, 53, 40002, response(0x2002, "www.example.com", typeA, 0, 0)) // referral
	b.udp(resolver, authSrv, 40003, 53, query(0x2003, "www.example.com", typeA))
	b.step(8 * time.Millisecond)
	b.udp(authSrv, resolver, 53, 40003, response(0x2003, "www.example.com", typeA, 0, 1))
	b.udp(resolver, clientA, 53, 54001, response(0x1111, "www.example.com", typeA, 0, 1))

	// --- Cache hit: client B asks the same name; no upstream traffic.
	b.step(500 * time.Millisecond)
	b.udp(clientB, resolver, 55002, 53, query(0x1212, "www.example.com", typeA))
	b.udp(resolver, clientB, 53, 55002, response(0x1212, "www.example.com", typeA, 0, 1))

	// --- AAAA + MX for another zone (single upstream hop each).
	b.step(300 * time.Millisecond)
	b.udp(clientA, resolver, 54002, 53, query(0x1a1a, "mail.example.org", typeAAAA))
	b.udp(resolver, authSrv, 40004, 53, query(0x2b2b, "mail.example.org", typeAAAA))
	b.udp(authSrv, resolver, 53, 40004, response(0x2b2b, "mail.example.org", typeAAAA, 0, 1))
	b.udp(resolver, clientA, 53, 54002, response(0x1a1a, "mail.example.org", typeAAAA, 0, 1))
	b.udp(clientC, resolver, 56001, 53, query(0x1b1b, "example.org", typeMX))
	b.udp(resolver, authSrv, 40005, 53, query(0x2c2c, "example.org", typeMX))
	b.udp(authSrv, resolver, 53, 40005, response(0x2c2c, "example.org", typeMX, 0, 2))
	b.udp(resolver, clientC, 53, 56001, response(0x1b1b, "example.org", typeMX, 0, 2))

	// --- NXDOMAIN.
	b.step(200 * time.Millisecond)
	b.udp(clientB, resolver, 55003, 53, query(0x3333, "no-such-host.example.com", typeA))
	b.udp(resolver, authSrv, 40006, 53, query(0x2d2d, "no-such-host.example.com", typeA))
	b.udp(authSrv, resolver, 53, 40006, response(0x2d2d, "no-such-host.example.com", typeA, 3, 0))
	b.udp(resolver, clientB, 53, 55003, response(0x3333, "no-such-host.example.com", typeA, 3, 0))

	// --- SERVFAIL: broken zone.
	b.step(200 * time.Millisecond)
	b.udp(clientC, resolver, 56002, 53, query(0x4444, "broken.example.net", typeTXT))
	b.udp(resolver, authSrv, 40007, 53, query(0x2e2e, "broken.example.net", typeTXT))
	b.udp(authSrv, resolver, 53, 40007, response(0x2e2e, "broken.example.net", typeTXT, 2, 0))
	b.udp(resolver, clientC, 53, 56002, response(0x4444, "broken.example.net", typeTXT, 2, 0))

	// --- Upstream timeout: the auth never answers; the client retries once,
	// then the resolver gives up with SERVFAIL.
	b.step(200 * time.Millisecond)
	b.udp(clientA, resolver, 54003, 53, query(0x5555, "slow.example.net", typeNS))
	b.udp(resolver, authSrv, 40008, 53, query(0x2f2f, "slow.example.net", typeNS))
	b.step(2 * time.Second)
	b.udp(clientA, resolver, 54003, 53, query(0x5555, "slow.example.net", typeNS)) // retry
	b.step(4 * time.Second)
	b.udp(resolver, clientA, 53, 54003, response(0x5555, "slow.example.net", typeNS, 2, 0))

	// Trailing traffic so replay ages past the query timeout.
	b.step(2 * time.Second)
	b.udp(clientB, resolver, 55004, 53, query(0x6666, "www.example.com", typeAAAA))
	b.udp(resolver, clientB, 53, 55004, response(0x6666, "www.example.com", typeAAAA, 0, 1))

	log.Printf("wrote %s", *out)
}
