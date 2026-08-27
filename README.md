# network-monitor

`netmon` is a terminal UI for live packet capture and session-flow analysis.
It listens on a network interface (or replays a pcap file), tracks every
TCP/UDP conversation, and presents a live timeline of flows with their TCP
state, identified application protocol, detected issues, and per-client
traffic totals.

```
 netmon │ LIVE eth0 │ flows 8 │ pkts 129 │ 22.6K │ 26 pps │ sort activity ▼
PROTO CLIENT             →  SERVER             STATE    APP                    AGE    IDLE   PKTS ⇄     BYTES ⇄   !
tcp   10.0.0.5:52104     →  93.184.216.34:443  ESTAB    TLS (example.com, h2) 12.4s   0.2s   145/98   12.1K/1.2M
tcp   10.0.0.5:52110     →  10.0.0.9:8080      SYN_SENT -                      3.1s   3.1s      3/0     180B/0B   !
udp   10.0.0.5:53555     →  8.8.8.8:53         ACTIVE   DNS (example.com)      0.3s   0.3s      1/1    71B/71B
```

Pure Go — no libpcap required. Live capture uses a raw `AF_PACKET` socket
(Linux only; needs root or `CAP_NET_RAW`), and pcap/pcapng files are read with
`gopacket`'s native readers. Both tools build and run on macOS and Windows
too: `--read` replay works everywhere, and attempting live capture off Linux
reports a clear error instead.

## Features

- **Flow timeline** — every TCP/UDP conversation as a live-updating row with
  observed TCP state (`SYN_SENT`, `SYN_RECV`, `ESTAB`, `FIN_WAIT`, `CLOSING`,
  `CLOSED`, `RST`), age, idle time, and per-direction packet/byte counters.
  Sortable by activity, bytes, duration, first-seen, or state.
- **Flow analysis** — select any flow to see per-direction counters
  (retransmits, dup-ACKs, out-of-order, zero-window), handshake RTT, and an
  annotated packet timeline of the last 200 packets (`[RETRANS]`, `[DUPACK]`,
  `[OOO]`, `[ZEROWIN]` markers on the offending packets).
- **Application protocol identification** — payload-based sniffing for TLS
  (with SNI + ALPN from the ClientHello), HTTP (with request line), SSH, DNS
  (with query name), and QUIC; falls back to a well-known-port guess shown
  with a `?` suffix (e.g. `https?`).
- **Issue detection** — retransmissions, duplicate-ACK runs, out-of-order
  segments, zero windows, connection refused (SYN→RST), half-open handshakes,
  unidirectional traffic, high handshake RTT, and long-idle sessions. Flows
  with issues carry a red `!` in the list; details are in the analysis view.
- **Top 10 clients** — toggle with `t`: running per-client flow/packet/byte
  totals with share-of-traffic bars.
- **Offline analysis** — `--read capture.pcap` (or `.pcapng`) replays a file
  through the same UI; all ages and idle times are computed from packet
  timestamps, so the timeline reflects capture time, not load time.

## Install / build

```sh
go build ./cmd/netmon
```

## Usage

```sh
sudo ./netmon                     # live capture on the default-route interface
sudo ./netmon -i eth0             # explicit interface
./netmon --list-interfaces        # show capturable interfaces
./netmon --read capture.pcap      # replay a capture file in the TUI
./netmon --read capture.pcap --oneshot   # plain-text flow summary, no TUI
```

Selected options (see `-h` for all):

| Flag | Default | Meaning |
| --- | --- | --- |
| `--filter-host <ip>` | – | only track flows involving this address |
| `--filter-port <n>` | – | only track flows involving this port |
| `--promisc` | off | promiscuous mode |
| `--max-flows` | 10000 | flow table cap (oldest-idle evicted beyond it) |
| `--udp-timeout` | 60s | UDP pseudo-flow idle timeout |
| `--closed-linger` | 30s | how long closed flows stay visible |
| `--rtt-threshold` | 200ms | handshake RTT flagged above this |
| `--idle-threshold` | 60s | established flows flagged idle after this |

### Keys

```
↑/↓ j/k     select flow            enter   analyze selected flow
t           top 10 clients         esc     back
s           cycle sort             o       reverse sort order
p           pause display          c       clear closed flows
?           help                   q       quit
```

## dnsmon: DNS from a recursive resolver's perspective

`dnsmon` is a DNS-specific companion tool. It correlates every DNS query with
its response by (5-tuple, QID) and splits the traffic into the two halves of a
recursive server: **clients querying the resolver on the left, the resolver
querying upstream/authoritative servers on the right**. Every transaction row
shows the client (or auth server) IP, qname, qtype, and DNS message ID, plus
its outcome — latency and rcode, still pending, or TIMEOUT.

```
 dnsmon │ LIVE eth0 │ resolver 192.0.2.53 │ cli 812q 809a │ auth 341q 339a │ 120 qps
 CLIENTS → RESOLVER  812 txns             │ RESOLVER → AUTHS  341 txns
   AGE CLIENT           QNAME      TYPE  QID STATUS         │  AGE AUTH SERVER  QNAME      TYPE  QID STATUS
  0.3s 10.1.0.11:54001  www.exam…  A    4369 12ms NOERROR   │ 0.3s 199.43.135…  www.exam…  A    8195 10ms NOERROR
  1.1s 10.1.0.12:55003  no-such-…  A   13107 6ms NXDOMAIN   │ 1.1s 199.43.135…  no-such-…  A   11565 6ms NXDOMAIN
  6.2s 10.1.0.11:54003  slow.exa…  NS  21845 6.0s SERVFAIL  │ 6.2s 199.43.135…  slow.exa…  NS  12079 TIMEOUT
```

```sh
go build ./cmd/dnsmon
sudo ./dnsmon                         # live capture on the default-route interface
sudo ./dnsmon -i eth0 --resolver 192.0.2.53
./dnsmon --read capture.pcap          # replay a capture in the TUI
./dnsmon --read capture.pcap --oneshot  # plain-text transaction summary
```

The resolver identity comes from `--resolver` (comma-separated IPs), or is
auto-detected: an address seen both *receiving* DNS queries and *sending*
them is a resolver. Live captures additionally seed detection with the
capture interface's own addresses, since the tool usually runs on the
resolver itself. Until an identity is known, transactions default to the
client side.

Beyond the per-transaction view, dnsmon surfaces: unanswered queries flagged
`TIMEOUT` (`--query-timeout`, default 5s), client retries (same socket, same
QID, same question), truncated responses (`+TC`), orphan responses that match
no outstanding query (spoof-shaped or late), and per-side rcode totals. Both
UDP and TCP (length-prefixed) DNS are parsed.

**Inspector** — press `enter` (or `i`) to open a bottom panel that follows
the selection as you scroll: a dig-style decode of the selected
transaction's query and response (header flags, opcode, question, EDNS
version/UDP size/DO, and every answer/authority/additional record with
rendered rdata — A, AAAA, CNAME, NS, PTR, MX, TXT, SOA, SRV, CAA; unknown
types as RFC 3597 hex) plus a full hex+ASCII dump of each message. Press `w`
to save the selected transaction's captured query and response frames to a
pcap in the working directory — original timestamps preserved, opens
directly in Wireshark/tcpdump.

Selected options (see `-h` for all):

| Flag | Default | Meaning |
| --- | --- | --- |
| `--resolver <ips>` | auto | pin the resolver identities |
| `--port <n>` | 53 | DNS port |
| `--query-timeout` | 5s | unanswered queries flagged TIMEOUT after this |
| `--max-txns` | 4096 | retained transactions (oldest evicted) |

### Keys

```
tab ←/→     switch pane            ↑/↓ j/k    select (newest first)
enter i     inspect selected       J/K        scroll inspector panel
w           save packets to pcap   home       follow newest
p           pause display          c          clear completed
?           help                   q          quit
```

## Try it without traffic

Generate a small scripted capture (HTTP with a retransmission, a refused
connection, a TLS ClientHello, DNS) and load it:

```sh
go run ./hack/genpcap -o demo.pcap
./netmon --read demo.pcap
```

For dnsmon, generate a scripted recursive-resolver capture (full recursion
walk, a cache hit, NXDOMAIN, SERVFAIL, and an upstream timeout):

```sh
go run ./hack/gendnspcap -o dns-demo.pcap
./dnsmon --read dns-demo.pcap
```

For a live loopback demo: `go run ./hack/echoserver` in one terminal,
`sudo ./netmon -i lo` in another, then `curl http://127.0.0.1:8080/`.

## Architecture

```
capture (AF_PACKET / pcap reader → decoder → PacketEvent channel)
   ├─→ flow tracker (single goroutine: flow table, TCP state machine,
   │    issue detectors, app-protocol sniffing, host totals, eviction)
   │     └─→ TUI (bubbletea; polls value-type snapshots every 500ms)
   └─→ dns tracker (dnsmon: transaction table keyed by 5-tuple + QID,
        query/response correlation, resolver detection, side classification)
         └─→ split-pane TUI (same snapshot-polling model)
```

- The tracker goroutine owns all flow state; the UI only ever sees deep
  copies requested over rendezvous channels, so the packet hot path is
  lock-free and the UI can never observe torn state.
- The capture pump never blocks on a slow consumer: overflow events are
  dropped and counted (shown as `drop N` in the status bar).
- All time-based logic (ages, idle, sweeps) runs on packet timestamps, which
  is what makes pcap replay behave identically to live capture.
- Issue detectors keep only per-direction scalars (wrap-aware sequence
  tracking), plus a fixed 200-entry ring of packet summaries per flow for the
  detail view — memory stays bounded regardless of traffic volume.

Notes on heuristics: retransmission/out-of-order detection is a single-gap
approximation of Wireshark's logic; duplicate-ACK detection requires ≥3
identical ACKs within 500ms at the current send position, which filters out
TCP keepalives and application heartbeats. On loopback, outgoing duplicate
frames are dropped (the same special-case libpcap applies), so each packet is
counted once.

## Development

```sh
go test ./...                                    # unit + end-to-end tests
go test -fuzz FuzzSniff -fuzztime 30s ./internal/analyze
```

The end-to-end test writes a scripted pcap (handshake, HTTP exchange,
retransmission, refused connection, DNS) and drives it through the full
capture→tracker pipeline, asserting states, protocols, issues, and top-client
attribution.
