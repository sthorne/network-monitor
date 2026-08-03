package capture

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// InterfaceInfo describes a capturable network interface.
type InterfaceInfo struct {
	Name  string
	Up    bool
	Loop  bool
	Addrs []string
}

// ListInterfaces returns all interfaces with their state and addresses.
func ListInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]InterfaceInfo, 0, len(ifaces))
	for _, ifc := range ifaces {
		info := InterfaceInfo{
			Name: ifc.Name,
			Up:   ifc.Flags&net.FlagUp != 0,
			Loop: ifc.Flags&net.FlagLoopback != 0,
		}
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				info.Addrs = append(info.Addrs, a.String())
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// AutoPick chooses a capture interface: the IPv4 default-route interface from
// /proc/net/route if one exists, otherwise the first up, non-loopback
// interface with an address.
func AutoPick() (string, error) {
	if name := defaultRouteInterface(); name != "" {
		return name, nil
	}
	ifaces, err := ListInterfaces()
	if err != nil {
		return "", err
	}
	for _, ifc := range ifaces {
		if ifc.Up && !ifc.Loop && len(ifc.Addrs) > 0 {
			return ifc.Name, nil
		}
	}
	return "", fmt.Errorf("no suitable capture interface found (try --list-interfaces)")
}

// defaultRouteInterface parses /proc/net/route for the interface owning the
// 0.0.0.0/0 route. Returns "" when unavailable (non-Linux, no default route).
func defaultRouteInterface() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// Iface Destination Gateway Flags ... ; default route has dest 00000000.
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}
