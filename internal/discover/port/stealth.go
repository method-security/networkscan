package discover

import (
	// Standard
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	// Generated
	common "github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// getStealthPortScan performs a stealth port scan using native Go networking capabilities.
// It provides delay control and top-N port targeting for more covert scanning.
func getStealthPortScan(ctx context.Context, config discoverfern.DiscoverPortConfig) ([]*discoverfern.SocketDetails, error) {
	log := svc1log.FromContext(ctx)

	// Default delay of 100ms between port scans if not specified
	delay := time.Duration(100) * time.Millisecond
	if config.Sleep != nil {
		delay = time.Duration(*config.Sleep) * time.Millisecond
	}

	// Get target ports to scan
	targetPorts, err := getStealthTargetPorts(config)
	if err != nil {
		return nil, err
	}

	log.Info("Starting stealth port scan",
		svc1log.SafeParam("target", config.Target),
		svc1log.SafeParam("ports", len(targetPorts)),
		svc1log.SafeParam("delay_ms", delay.Milliseconds()))

	var openPorts []*discoverfern.PortDetails

	// Scan each port with delay
	for i, port := range targetPorts {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		if isPortOpen(ctx, config.Target, port) {
			openPorts = append(openPorts, &discoverfern.PortDetails{
				Port:     port,
				Protocol: common.TransportTypeTcp,
			})
			log.Debug("Found open port", svc1log.SafeParam("port", port))
		}
	}

	socketDetails := &discoverfern.SocketDetails{
		Host:  config.Target,
		Ip:    config.Target, // For stealth scan, we'll use target as IP for simplicity
		Ports: openPorts,
	}

	return []*discoverfern.SocketDetails{socketDetails}, nil
}

// getStealthTargetPorts determines which ports to scan based on the stealth configuration
func getStealthTargetPorts(config discoverfern.DiscoverPortConfig) ([]int, error) {
	var ports []int

	// If specific ports are provided, use those
	if config.Ports != nil && *config.Ports != "" {
		var err error
		ports, err = parsePortList(*config.Ports)
		if err != nil {
			return nil, fmt.Errorf("invalid port specification: %w", err)
		}
	} else if config.TopPorts != nil {
		// Fall back to standard top ports configuration
		switch *config.TopPorts {
		case "100":
			ports = getTopNPorts(100)
		case "1000":
			ports = getTopNPorts(1000)
		case "full":
			ports = getTopNPorts(65535)
		default:
			// Try to parse as number
			if topN, err := strconv.Atoi(*config.TopPorts); err == nil {
				ports = getTopNPorts(topN)
			} else {
				return nil, fmt.Errorf("invalid top-ports value: %s", *config.TopPorts)
			}
		}
	} else {
		// Default to top 100 ports for stealth (smaller default for covert ops)
		ports = getTopNPorts(100)
	}

	// Sort ports for consistent scanning order
	sort.Ints(ports)
	return ports, nil
}

// parsePortList parses a comma-separated port list with support for ranges
func parsePortList(portStr string) ([]int, error) {
	var ports []int
	portStrings := strings.Split(portStr, ",")

	for _, ps := range portStrings {
		ps = strings.TrimSpace(ps)
		if strings.Contains(ps, "-") {
			// Handle port ranges like "1-1024"
			rangeParts := strings.Split(ps, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", ps)
			}
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", rangeParts[1])
			}
			if start > end {
				return nil, fmt.Errorf("invalid port range: start %d > end %d", start, end)
			}
			for i := start; i <= end; i++ {
				if i >= 1 && i <= 65535 {
					ports = append(ports, i)
				}
			}
		} else {
			// Single port
			port, err := strconv.Atoi(ps)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", ps)
			}
			if port >= 1 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}
	return ports, nil
}

// isPortOpen checks if a specific port is open using a simple TCP connection
func isPortOpen(ctx context.Context, host string, port int) bool {
	timeout := 3 * time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// getTopNPorts returns the most commonly used TCP ports up to N ports
// Based on nmap's default top ports and IANA port assignments
func getTopNPorts(n int) []int {
	// Curated list based on nmap frequency data and security research
	// Source: nmap default ports, SANS top ports, common enterprise services
	topPorts := []int{
		// Web services (most common)
		80, 443, 8080, 8443, 8000, 8888,
		// Remote access
		22, 3389, 5985, 5986,
		// File/Directory services
		21, 139, 445, 2049, 111,
		// Mail services
		25, 110, 143, 993, 995, 587,
		// DNS and DHCP
		53, 67, 68,
		// Database services
		1433, 3306, 5432, 6379, 27017,
		// Directory services
		389, 636, 88, 464,
		// Legacy/Telnet
		23, 513, 514, 515,
		// SNMP and management
		161, 162, 623,
		// Development and APIs
		3000, 4000, 5000, 6000, 7000, 8001, 9000, 9090,
		// Windows services
		135, 1025, 1026, 1027, 1028, 1029,
		// High/dynamic ports
		32768, 49152, 49153, 49154, 49155,
	}

	if n <= len(topPorts) {
		return topPorts[:n]
	}

	// For requests beyond our curated list, add ports sequentially
	result := make([]int, len(topPorts))
	copy(result, topPorts)

	used := make(map[int]bool)
	for _, p := range topPorts {
		used[p] = true
	}

	// Add remaining ports in order
	for port := 1; port <= 65535 && len(result) < n; port++ {
		if !used[port] {
			result = append(result, port)
		}
	}

	return result[:n]
}
