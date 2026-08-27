//go:build linux

package capture

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/unix"
)

// LiveSource captures from a network interface with a raw AF_PACKET socket
// (pure Go, no libpcap). Requires root or CAP_NET_RAW.
//
// It intentionally does not use pcapgo.EthernetHandle: that API discards
// sll_pkttype, which is needed to drop PACKET_OUTGOING frames on loopback —
// otherwise every packet on lo appears twice (once per direction of the
// kernel's internal loop), the same duplication libpcap special-cases.
type LiveSource struct {
	f        *os.File
	iface    string
	loopback bool
	snaplen  int
	buf      []byte
	oob      []byte
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// OpenLive opens iface for capture with the given snap length.
func OpenLive(iface string, snaplen int, promiscuous bool) (*LiveSource, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", iface, err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("opening %s: %w (live capture needs root or CAP_NET_RAW)", iface, err)
		}
		return nil, fmt.Errorf("opening %s: %w", iface, err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifc.Index,
	}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("binding to %s: %w", iface, err)
	}
	// Nanosecond receive timestamps delivered as control messages.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1)
	if promiscuous {
		mreq := unix.PacketMreq{Ifindex: int32(ifc.Index), Type: unix.PACKET_MR_PROMISC}
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("enabling promiscuous mode on %s: %w", iface, err)
		}
	}
	// Non-blocking + os.File integrates with the runtime poller, so Close()
	// unblocks a pending read.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if snaplen <= 0 || snaplen > 262144 {
		snaplen = 65535
	}
	return &LiveSource{
		f:        os.NewFile(uintptr(fd), "af_packet:"+iface),
		iface:    iface,
		loopback: ifc.Flags&net.FlagLoopback != 0,
		snaplen:  snaplen,
		buf:      make([]byte, snaplen),
		oob:      make([]byte, 512),
	}, nil
}

func (s *LiveSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	rawConn, err := s.f.SyscallConn()
	if err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}
	for {
		var (
			n, oobn int
			from    unix.Sockaddr
			recvErr error
		)
		err = rawConn.Read(func(fd uintptr) bool {
			n, oobn, _, from, recvErr = unix.Recvmsg(int(fd), s.buf, s.oob, unix.MSG_TRUNC)
			return recvErr != unix.EAGAIN
		})
		if err != nil {
			return nil, gopacket.CaptureInfo{}, err
		}
		if recvErr != nil {
			return nil, gopacket.CaptureInfo{}, recvErr
		}

		// Loopback delivers every packet twice (outgoing + incoming copy);
		// keep only the incoming one, as libpcap does.
		if s.loopback {
			if sll, ok := from.(*unix.SockaddrLinklayer); ok && sll.Pkttype == unix.PACKET_OUTGOING {
				continue
			}
		}

		wireLen := n // MSG_TRUNC: n is the full on-wire length
		capLen := n
		if capLen > len(s.buf) {
			capLen = len(s.buf)
		}
		data := make([]byte, capLen)
		copy(data, s.buf[:capLen])

		ci := gopacket.CaptureInfo{
			Timestamp:     s.timestamp(oobn),
			CaptureLength: capLen,
			Length:        wireLen,
		}
		return data, ci, nil
	}
}

// timestamp extracts the kernel SO_TIMESTAMPNS control message, falling back
// to wall clock.
func (s *LiveSource) timestamp(oobn int) time.Time {
	if oobn > 0 {
		msgs, err := unix.ParseSocketControlMessage(s.oob[:oobn])
		if err == nil {
			for _, m := range msgs {
				if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SO_TIMESTAMPNS &&
					len(m.Data) >= int(unsafe.Sizeof(unix.Timespec{})) {
					ts := (*unix.Timespec)(unsafe.Pointer(&m.Data[0]))
					return time.Unix(ts.Sec, ts.Nsec)
				}
			}
		}
	}
	return time.Now()
}

func (s *LiveSource) LinkType() layers.LinkType { return layers.LinkTypeEthernet }
func (s *LiveSource) Close() error              { return s.f.Close() }
func (s *LiveSource) Name() string              { return s.iface }
