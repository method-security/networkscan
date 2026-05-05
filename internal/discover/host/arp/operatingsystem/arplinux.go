//go:build linux

package operatingsystem

import (
	// Standard
	"bufio"
	"fmt"
	"os"
	"strings"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

// GetArpEntries reads the ARP table on Linux by parsing /proc/net/arp.
// The kernel exposes its ARP cache as a plain-text virtual file; no external
// processes are spawned.
//
// /proc/net/arp format (space-separated columns):
//
//	IP address   HW type  Flags   HW address         Mask  Device
//	192.168.1.1  0x1      0x2     aa:bb:cc:dd:ee:ff  *     eth0
func GetArpEntries() ([]*discoverfern.ArpEntry, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("opening /proc/net/arp: %w", err)
	}
	defer func() { _ = f.Close() }()

	var entries []*discoverfern.ArpEntry
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip the header line

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}

		ip := fields[0]
		hwType := fields[1]
		flags := fields[2]
		mac := fields[3]
		mask := fields[4]
		iface := fields[5]

		// Skip incomplete ARP entries; flags 0x0 means no valid mapping yet.
		if flags == "0x0" {
			continue
		}

		entries = append(entries, &discoverfern.ArpEntry{
			Ip:        ip,
			Mac:       mac,
			HwType:    &hwType,
			Flags:     &flags,
			Mask:      &mask,
			Interface: &iface,
		})
	}

	return entries, scanner.Err()
}
