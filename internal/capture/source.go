package capture

import (
	"context"
	"errors"
	"io"
	"sync/atomic"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// PacketSource abstracts a live interface handle or a pcap file reader.
type PacketSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
	Close() error
}

// Stats holds pump counters, updated atomically.
type Stats struct {
	Packets atomic.Uint64 // events delivered
	Dropped atomic.Uint64 // events dropped because the channel was full
}

// Run pumps packets from src through dec into out until ctx is cancelled or
// the source ends (io.EOF for files). The out channel is closed on return.
// The read loop never blocks on a full channel: overflow events are dropped
// and counted so a stalled consumer cannot back up the kernel ring.
func Run(ctx context.Context, src PacketSource, dec *Decoder, out chan<- PacketEvent, stats *Stats) error {
	defer close(out)
	consecutiveErrs := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		data, ci, err := src.ReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			if ctx.Err() != nil {
				return nil
			}
			// Transient read errors (e.g. truncated frame) are skipped, but a
			// persistently failing source (closed socket) must not busy-loop.
			if consecutiveErrs++; consecutiveErrs > 100 {
				return err
			}
			continue
		}
		consecutiveErrs = 0
		ev, ok := dec.Decode(data, ci)
		if !ok {
			continue
		}
		select {
		case out <- ev:
			stats.Packets.Add(1)
		default:
			stats.Dropped.Add(1)
		}
	}
}
