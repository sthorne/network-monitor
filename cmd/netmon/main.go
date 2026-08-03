// Command netmon is a live packet-capture TUI: it tracks session flows on a
// network interface (or from a pcap file), shows their TCP state and detected
// issues, identifies application protocols, and reports top clients.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/sthorne/network-monitor/internal/capture"
	"github.com/sthorne/network-monitor/internal/flow"
	"github.com/sthorne/network-monitor/internal/ui"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "netmon:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		iface      = flag.String("i", "", "interface to capture on (default: auto-pick default-route interface)")
		listIfaces = flag.Bool("list-interfaces", false, "list capturable interfaces and exit")
		readFile   = flag.String("read", "", "read packets from a pcap/pcapng file instead of live capture")
		oneshot    = flag.Bool("oneshot", false, "with --read: print a flow summary and exit (no TUI)")
		filterHost = flag.String("filter-host", "", "only track flows involving this IP")
		filterPort = flag.Uint("filter-port", 0, "only track flows involving this port")
		snaplen    = flag.Int("snaplen", 65535, "capture snap length")
		promisc    = flag.Bool("promisc", false, "enable promiscuous mode")
		maxFlows   = flag.Int("max-flows", 10000, "maximum tracked flows")
		udpTimeout = flag.Duration("udp-timeout", 60*time.Second, "UDP pseudo-flow idle timeout")
		linger     = flag.Duration("closed-linger", 30*time.Second, "how long closed flows stay visible")
		rttThresh  = flag.Duration("rtt-threshold", 200*time.Millisecond, "handshake RTT flagged above this")
		idleThresh = flag.Duration("idle-threshold", 60*time.Second, "established flows flagged idle after this")
	)
	flag.Parse()

	if *listIfaces {
		return printInterfaces()
	}
	if *oneshot && *readFile == "" {
		return fmt.Errorf("--oneshot requires --read")
	}

	var filter capture.Filter
	if *filterHost != "" {
		addr, err := netip.ParseAddr(*filterHost)
		if err != nil {
			return fmt.Errorf("invalid --filter-host: %w", err)
		}
		filter.Host = addr
	}
	if *filterPort > 65535 {
		return fmt.Errorf("invalid --filter-port %d", *filterPort)
	}
	filter.Port = uint16(*filterPort)

	cfg := flow.Config{
		MaxFlows:      *maxFlows,
		MaxHosts:      4096,
		UDPTimeout:    *udpTimeout,
		ClosedLinger:  *linger,
		RTTThreshold:  *rttThresh,
		IdleThreshold: *idleThresh,
		HalfOpenAfter: 5 * time.Second,
		FileMode:      *readFile != "",
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
	}
	if err != nil {
		return err
	}
	defer src.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan capture.PacketEvent, 4096)
	stats := &capture.Stats{}
	dec := capture.NewDecoder(src.LinkType(), filter)
	tracker := flow.NewTracker(cfg, events)

	pumpErr := make(chan error, 1)
	go func() { pumpErr <- capture.Run(ctx, src, dec, events, stats) }()
	go tracker.Run(ctx)

	if *oneshot {
		return runOneshot(tracker, pumpErr)
	}

	err = ui.Run(ui.Params{
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

// runOneshot waits for the pcap to finish loading, then prints a plain-text
// flow summary — the no-TTY escape hatch and e2e-demo path.
func runOneshot(tracker *flow.Tracker, pumpErr <-chan error) error {
	if err := <-pumpErr; err != nil {
		return err
	}
	// The tracker drains the buffered channel after the pump closes it; a
	// snapshot request rendezvouses with the same goroutine, so loop until
	// the event channel has been fully consumed (EOF observed).
	var snap flow.Snapshot
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

	rows := snap.Flows
	sort.Slice(rows, func(i, j int) bool { return rows[i].FirstSeen.Before(rows[j].FirstSeen) })

	fmt.Printf("%d flows, %d packets, %s total\n\n", snap.ActiveFlows, snap.TotalPkts, ui.Bytes(snap.TotalBytes))
	fmt.Printf("%-5s %-24s %-24s %-9s %-22s %9s %9s %11s %11s  %s\n",
		"PROTO", "CLIENT", "SERVER", "STATE", "APP", "PKTS>", "PKTS<", "BYTES>", "BYTES<", "ISSUES")
	for _, r := range rows {
		fmt.Printf("%-5s %-24s %-24s %-9s %-22s %9d %9d %11s %11s  %s\n",
			r.Proto,
			ui.Endpoint(r.ClientAddr, r.ClientPort),
			ui.Endpoint(r.ServerAddr, r.ServerPort),
			r.State,
			truncate(r.App.Label(), 22),
			r.PktsOut, r.PktsIn,
			ui.Bytes(r.BytesOut), ui.Bytes(r.BytesIn),
			r.Issues.String())
	}

	fmt.Printf("\nTop clients:\n")
	for i, h := range snap.TopHosts {
		fmt.Printf("%2d. %-24s flows=%d pkts=%d bytes=%s\n",
			i+1, h.Addr, h.Flows, h.Packets, ui.Bytes(h.Bytes))
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
