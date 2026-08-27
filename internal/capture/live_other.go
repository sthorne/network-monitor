//go:build !linux

package capture

import (
	"fmt"
	"runtime"
)

// OpenLive is unsupported off Linux: live capture uses AF_PACKET raw sockets.
// Pcap/pcapng replay (--read) is pure Go and works on every platform.
func OpenLive(iface string, snaplen int, promiscuous bool) (PacketSource, error) {
	return nil, fmt.Errorf("live capture is not supported on %s (it uses Linux AF_PACKET sockets); use --read with a pcap file", runtime.GOOS)
}
