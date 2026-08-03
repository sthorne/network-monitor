// Command genpcap writes a small scripted capture (HTTP with a retransmit and
// clean close, a refused connection, a TLS ClientHello, DNS) for demoing
// netmon --read without live traffic.
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
	macA = net.HardwareAddr{2, 0, 0, 0, 0, 1}
	macB = net.HardwareAddr{2, 0, 0, 0, 0, 2}

	client = net.IP{10, 0, 0, 5}
	server = net.IP{10, 0, 0, 9}
	dnsSrv = net.IP{8, 8, 8, 8}
	webSrv = net.IP{93, 184, 216, 34}
)

type builder struct {
	w  *pcapgo.Writer
	ts time.Time
}

func (b *builder) write(ls ...gopacket.SerializableLayer) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		log.Fatal(err)
	}
	data := buf.Bytes()
	ci := gopacket.CaptureInfo{Timestamp: b.ts, CaptureLength: len(data), Length: len(data)}
	if err := b.w.WritePacket(ci, data); err != nil {
		log.Fatal(err)
	}
	b.ts = b.ts.Add(3 * time.Millisecond)
}

type seg struct {
	src, dst                 net.IP
	sp, dp                   layers.TCPPort
	seq, ack                 uint32
	syn, ackF, fin, rst, psh bool
	payload                  []byte
}

func (b *builder) tcp(s seg) {
	eth := &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: s.src, DstIP: s.dst}
	tcp := &layers.TCP{SrcPort: s.sp, DstPort: s.dp, Seq: s.seq, Ack: s.ack,
		SYN: s.syn, ACK: s.ackF, FIN: s.fin, RST: s.rst, PSH: s.psh, Window: 65535}
	tcp.SetNetworkLayerForChecksum(ip)
	if len(s.payload) > 0 {
		b.write(eth, ip, tcp, gopacket.Payload(s.payload))
	} else {
		b.write(eth, ip, tcp)
	}
}

func (b *builder) udp(src, dst net.IP, sp, dp layers.UDPPort, payload []byte) {
	eth := &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: src, DstIP: dst}
	udp := &layers.UDP{SrcPort: sp, DstPort: dp}
	udp.SetNetworkLayerForChecksum(ip)
	b.write(eth, ip, udp, gopacket.Payload(payload))
}

func clientHello(sni, alpn string) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 1, 0)
	var exts []byte
	name := []byte(sni)
	entry := append([]byte{0}, u16(len(name))...)
	entry = append(entry, name...)
	list := append(u16(len(entry)), entry...)
	exts = append(exts, u16(0)...)
	exts = append(exts, u16(len(list))...)
	exts = append(exts, list...)
	p := []byte(alpn)
	entry = append([]byte{byte(len(p))}, p...)
	list = append(u16(len(entry)), entry...)
	exts = append(exts, u16(16)...)
	exts = append(exts, u16(len(list))...)
	exts = append(exts, list...)
	body = append(body, u16(len(exts))...)
	body = append(body, exts...)
	hs := append([]byte{0x01, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x01}, u16(len(hs))...)
	return append(rec, hs...)
}

func u16(n int) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(n))
	return b
}

func main() {
	out := flag.String("o", "demo.pcap", "output file")
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

	// HTTP session with one retransmission and a clean close.
	req := []byte("GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n")
	resp = append(resp, make([]byte, 1024)...)
	b.tcp(seg{src: client, dst: server, sp: 40000, dp: 80, seq: 1000, syn: true})
	b.tcp(seg{src: server, dst: client, sp: 80, dp: 40000, seq: 5000, ack: 1001, syn: true, ackF: true})
	b.tcp(seg{src: client, dst: server, sp: 40000, dp: 80, seq: 1001, ack: 5001, ackF: true})
	b.tcp(seg{src: client, dst: server, sp: 40000, dp: 80, seq: 1001, ack: 5001, ackF: true, psh: true, payload: req})
	b.tcp(seg{src: client, dst: server, sp: 40000, dp: 80, seq: 1001, ack: 5001, ackF: true, psh: true, payload: req})
	b.tcp(seg{src: server, dst: client, sp: 80, dp: 40000, seq: 5001, ack: 1001 + uint32(len(req)), ackF: true, psh: true, payload: resp})
	b.tcp(seg{src: client, dst: server, sp: 40000, dp: 80, seq: 1001 + uint32(len(req)), ack: 5001 + uint32(len(resp)), ackF: true, fin: true})
	b.tcp(seg{src: server, dst: client, sp: 80, dp: 40000, seq: 5001 + uint32(len(resp)), ack: 1002 + uint32(len(req)), ackF: true, fin: true})
	b.tcp(seg{src: client, dst: server, sp: 40000, dp: 80, seq: 1002 + uint32(len(req)), ack: 5002 + uint32(len(resp)), ackF: true})

	// Refused connection.
	b.tcp(seg{src: client, dst: server, sp: 40001, dp: 9999, seq: 7000, syn: true})
	b.tcp(seg{src: server, dst: client, sp: 9999, dp: 40001, seq: 0, ack: 7001, rst: true, ackF: true})

	// TLS session left established (half of it, mid-download).
	hello := clientHello("example.com", "h2")
	b.tcp(seg{src: client, dst: webSrv, sp: 40002, dp: 443, seq: 100, syn: true})
	b.tcp(seg{src: webSrv, dst: client, sp: 443, dp: 40002, seq: 900, ack: 101, syn: true, ackF: true})
	b.tcp(seg{src: client, dst: webSrv, sp: 40002, dp: 443, seq: 101, ack: 901, ackF: true})
	b.tcp(seg{src: client, dst: webSrv, sp: 40002, dp: 443, seq: 101, ack: 901, ackF: true, psh: true, payload: hello})
	b.tcp(seg{src: webSrv, dst: client, sp: 443, dp: 40002, seq: 901, ack: 101 + uint32(len(hello)), ackF: true, psh: true, payload: make([]byte, 1400)})

	// A half-open SYN with no answer.
	b.tcp(seg{src: client, dst: server, sp: 40003, dp: 8443, seq: 4242, syn: true})

	// DNS query/response.
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"example", "com"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	b.udp(client, dnsSrv, 53555, 53, q)
	r := append([]byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, q[12:]...)
	b.udp(dnsSrv, client, 53, 53555, r)

	log.Printf("wrote %s", *out)
}
