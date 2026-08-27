// Command dnsmon is a DNS-specific capture TUI for recursive resolvers: it
// correlates DNS queries with responses and splits the traffic into the
// client side (queries arriving at the resolver) and the upstream side (the
// resolver querying authoritative/upstream servers), showing client IP,
// qname, qtype, and QID for every transaction.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sthorne/network-monitor/internal/capture"
	"github.com/sthorne/network-monitor/internal/dnsmon"
	"github.com/sthorne/network-monitor/internal/dnsui"
	"github.com/sthorne/network-monitor/internal/ui"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dnsmon:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		iface      = flag.String("i", "", "interface to capture on (default: auto-pick default-route interface)")
		listIfaces = flag.Bool("list-interfaces", false, "list capturable interfaces and exit")
		readFile   = flag.String("read", "", "read packets from a pcap/pcapng file instead of live capture")
		oneshot    = flag.Bool("oneshot", false, "with --read: print a transaction summary and exit (no TUI)")
		resolvers  = flag.String("resolver", "", "comma-separated resolver IPs (default: auto-detect)")
		port       = flag.Uint("port", 53, "DNS port")
		qTimeout   = flag.Duration("query-timeout", 5*time.Second, "unanswered queries flagged TIMEOUT after this")
		maxTxns    = flag.Int("max-txns", 4096, "maximum retained transactions (oldest evicted)")
		snaplen    = flag.Int("snaplen", 65535, "capture snap length")
		promisc    = flag.Bool("promisc", false, "enable promiscuous mode")
	)
	flag.Parse()

	if *listIfaces {
		return printInterfaces()
	}
	if *oneshot && *readFile == "" {
		return fmt.Errorf("--oneshot requires --read")
	}
	if *port == 0 || *port > 65535 {
		return fmt.Errorf("invalid --port %d", *port)
	}

	cfg := dnsmon.Config{
		Port:     uint16(*port),
		Timeout:  *qTimeout,
		MaxTxns:  *maxTxns,
		FileMode: *readFile != "",
	}
	if *resolvers != "" {
		for _, s := range strings.Split(*resolvers, ",") {
			addr, err := netip.ParseAddr(strings.TrimSpace(s))
			if err != nil {
				return fmt.Errorf("invalid --resolver %q: %w", s, err)
			}
			cfg.Resolvers = append(cfg.Resolvers, addr)
		}
	}

	var (
		src        capture.PacketSource
		sourceName string
		err        error
	)
	if *readFile != "" {
		src, err = capture.OpenFile(*readFile)
		sourceName = *readFile
	} else {
		name := *iface
		if name == "" {
			if name, err = capture.AutoPick(); err != nil {
				return err
			}
		}
		src, err = capture.OpenLive(name, *snaplen, *promisc)
		sourceName = name
		// On a live capture the tool usually runs on the resolver itself:
		// seed detection with the interface's own addresses.
		if len(cfg.Resolvers) == 0 {
			cfg.LocalHints = interfaceAddrs(name)
		}
	}
	if err != nil {
		return err
	}
	defer src.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan capture.PacketEvent, 4096)
	stats := &capture.Stats{}
	dec := capture.NewDecoder(src.LinkType(), capture.Filter{Port: cfg.Port})
	tracker := dnsmon.NewTracker(cfg, events)

	pumpErr := make(chan error, 1)
	go func() { pumpErr <- capture.Run(ctx, src, dec, events, stats) }()
	go tracker.Run(ctx)

	if *oneshot {
		return runOneshot(tracker, pumpErr)
	}

	err = dnsui.Run(dnsui.Params{
		Tracker:    tracker,
		Stats:      stats,
		SourceName: sourceName,
		Live:       *readFile == "",
	})
	// Unblock a live read stuck in recvfrom so the pump goroutine exits.
	cancel()
	src.Close()
	return err
}

func printInterfaces() error {
	infos, err := capture.ListInterfaces()
	if err != nil {
		return err
	}
	for _, ifc := range infos {
		state := "down"
		if ifc.Up {
			state = "up"
		}
		kind := ""
		if ifc.Loop {
			kind = " loopback"
		}
		fmt.Printf("%-12s %-4s%s", ifc.Name, state, kind)
		for _, a := range ifc.Addrs {
			fmt.Printf("  %s", a)
		}
		fmt.Println()
	}
	return nil
}

// interfaceAddrs returns the addresses configured on the named interface.
func interfaceAddrs(name string) []netip.Addr {
	infos, err := capture.ListInterfaces()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, ifc := range infos {
		if ifc.Name != name {
			continue
		}
		for _, s := range ifc.Addrs {
			if pfx, err := netip.ParsePrefix(s); err == nil {
				out = append(out, pfx.Addr().Unmap())
			} else if addr, err := netip.ParseAddr(s); err == nil {
				out = append(out, addr.Unmap())
			}
		}
	}
	return out
}

// runOneshot waits for the pcap to finish loading, then prints both sides of
// the transaction table — the no-TTY escape hatch and e2e-demo path.
func runOneshot(tracker *dnsmon.Tracker, pumpErr <-chan error) error {
	if err := <-pumpErr; err != nil {
		return err
	}
	var snap dnsmon.Snapshot
	for {
		s, ok := tracker.Snapshot()
		if !ok {
			return fmt.Errorf("tracker stopped unexpectedly")
		}
		if s.EOF {
			snap = s
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	resolvers := make([]string, 0, len(snap.Resolvers))
	for _, a := range snap.Resolvers {
		resolvers = append(resolvers, a.String())
	}
	label := "auto (none detected)"
	if len(resolvers) > 0 {
		label = strings.Join(resolvers, ", ")
	}
	fmt.Printf("%d DNS messages, %d transactions, resolver: %s\n",
		snap.TotalMsgs, len(snap.Rows), label)

	printSide(snap, dnsmon.SideClient, "CLIENTS → RESOLVER", "CLIENT")
	printSide(snap, dnsmon.SideUpstream, "RESOLVER → AUTHS", "AUTH SERVER")

	fmt.Println()
	for side := dnsmon.SideClient; side <= dnsmon.SideUpstream; side++ {
		st := snap.Sides[side]
		fmt.Printf("%-8s queries=%d answered=%d pending=%d timeout=%d retries=%d",
			side, st.Queries, st.Answered, st.Pending, st.Timeout, st.Retries)
		fmt.Printf("  rcodes:%s\n", rcodeSummary(st.RCodes))
	}
	if snap.Orphans > 0 || snap.Malformed > 0 {
		fmt.Printf("orphan responses=%d malformed=%d\n", snap.Orphans, snap.Malformed)
	}
	return nil
}

func printSide(snap dnsmon.Snapshot, side dnsmon.Side, title, addrLabel string) {
	fmt.Printf("\n%s\n", title)
	fmt.Printf("%-22s %-40s %-6s %5s %-9s %8s %s\n",
		addrLabel, "QNAME", "TYPE", "QID", "STATE", "LATENCY", "RCODE")
	for _, r := range snap.Rows {
		if r.Side != side {
			continue
		}
		addr := r.Server.String()
		if side == dnsmon.SideClient {
			addr = ui.Endpoint(r.Querier, r.QuerierPort)
		}
		lat, rcode := "-", "-"
		if r.State == dnsmon.TxnAnswered {
			lat = ui.Age(r.Latency())
			rcode = dnsmon.RCodeName(r.RCode)
			if r.TC {
				rcode += "+TC"
			}
		}
		fmt.Printf("%-22s %-40s %-6s %5d %-9s %8s %s\n",
			addr, truncate(r.QName, 40), dnsmon.TypeName(r.QType), r.QID,
			r.State, lat, rcode)
	}
}

func rcodeSummary(rcodes map[uint8]uint64) string {
	if len(rcodes) == 0 {
		return " -"
	}
	codes := make([]uint8, 0, len(rcodes))
	for rc := range rcodes {
		codes = append(codes, rc)
	}
	sort.Slice(codes, func(i, j int) bool { return codes[i] < codes[j] })
	var b strings.Builder
	for _, rc := range codes {
		fmt.Fprintf(&b, " %s=%d", dnsmon.RCodeName(rc), rcodes[rc])
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
