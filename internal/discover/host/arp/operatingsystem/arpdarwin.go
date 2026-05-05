//go:build darwin

package operatingsystem

import (
	// Standard
	"fmt"
	"net"
	"syscall"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"

	// golang.org/x/net/route is a pure-Go interface to the BSD routing socket,
	// giving access to the kernel ARP/neighbor cache without any exec calls.
	"golang.org/x/net/route"
)

// GetArpEntries reads the ARP table on Darwin/macOS by querying the kernel
// routing socket via golang.org/x/net/route. No external processes are
// spawned.
//
// The routing socket is queried with:
//
//	sysctl(CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO)
//
// RTF_LLINFO marks link-layer address mappings (i.e. ARP entries) for IPv4.
func GetArpEntries() ([]*discoverfern.ArpEntry, error) {
	rib, err := route.FetchRIB(syscall.AF_INET, syscall.NET_RT_FLAGS, syscall.RTF_LLINFO)
	if err != nil {
		return nil, fmt.Errorf("fetching ARP RIB: %w", err)
	}

	msgs, err := route.ParseRIB(syscall.NET_RT_FLAGS, rib)
	if err != nil {
		return nil, fmt.Errorf("parsing ARP RIB: %w", err)
	}

	var entries []*discoverfern.ArpEntry
	for _, msg := range msgs {
		m, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}

		var ip, mac, ifaceName string

		// RTAX_DST (index 0) — destination IPv4 address.
		if syscall.RTAX_DST < len(m.Addrs) && m.Addrs[syscall.RTAX_DST] != nil {
			if a, ok := m.Addrs[syscall.RTAX_DST].(*route.Inet4Addr); ok {
				ip = net.IP(a.IP[:]).String()
			}
		}

		// RTAX_GATEWAY (index 1) — for ARP entries this is the link-layer
		// (MAC) address and the interface index.
		if syscall.RTAX_GATEWAY < len(m.Addrs) && m.Addrs[syscall.RTAX_GATEWAY] != nil {
			if a, ok := m.Addrs[syscall.RTAX_GATEWAY].(*route.LinkAddr); ok {
				if len(a.Addr) >= 6 {
					mac = net.HardwareAddr(a.Addr).String()
				}
				if a.Index > 0 {
					if iface, err := net.InterfaceByIndex(a.Index); err == nil {
						ifaceName = iface.Name
					}
				}
			}
		}

		if ip == "" || mac == "" {
			continue
		}

		entry := &discoverfern.ArpEntry{
			Ip:  ip,
			Mac: mac,
		}
		if ifaceName != "" {
			entry.Interface = &ifaceName
		}
		entries = append(entries, entry)
	}

	return entries, nil
}
