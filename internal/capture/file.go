package capture

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// pcapng section header block magic (byte order independent first 4 bytes).
const ngMagic = 0x0A0D0D0A

// FileSource replays a pcap or pcapng file through the PacketSource interface.
type FileSource struct {
	f    *os.File
	read func() ([]byte, gopacket.CaptureInfo, error)
	link layers.LinkType
	name string
}

// OpenFile opens a .pcap or .pcapng capture file, autodetected by magic bytes.
func OpenFile(path string) (*FileSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReader(f)
	magic, err := br.Peek(4)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	src := &FileSource{f: f, name: path}
	if binary.LittleEndian.Uint32(magic) == ngMagic {
		r, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("parsing pcapng %s: %w", path, err)
		}
		src.read = r.ReadPacketData
		src.link = r.LinkType()
	} else {
		r, err := pcapgo.NewReader(br)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("parsing pcap %s: %w", path, err)
		}
		src.read = r.ReadPacketData
		src.link = r.LinkType()
	}
	return src, nil
}

func (s *FileSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := s.read()
	if err != nil && err != io.EOF {
		// Reader errors past a partial trailing record are treated as EOF so a
		// truncated capture still loads what it has.
		if err == io.ErrUnexpectedEOF {
			return nil, ci, io.EOF
		}
	}
	return data, ci, err
}

func (s *FileSource) LinkType() layers.LinkType { return s.link }
func (s *FileSource) Close() error              { return s.f.Close() }
func (s *FileSource) Name() string              { return s.name }
