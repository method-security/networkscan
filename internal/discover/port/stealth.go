package discover

import (
	// Standard
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"

	// Internal
	"github.com/Method-Security/networkscan/utils"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// TopPortsConfig represents the structure of the top_ports.json configuration file
type TopPortsConfig struct {
	Description string `json:"description"`
	Source      string `json:"source"`
	Ports       []int  `json:"ports"`
}

var (
	topPortsCache     []int
	topPortsCacheLock sync.RWMutex
)

// getStealthPortScan performs a stealth port scan using native Go networking capabilities.
// It provides delay control and top-N port targeting for more covert scanning.
func getStealthPortScan(ctx context.Context, config discoverfern.DiscoverPortConfig) ([]*discoverfern.SocketDetails, error) {
	log := svc1log.FromContext(ctx)

	// Default delay of 100ms between port scans if not specified
	delay := time.Duration(100) * time.Millisecond
	if config.Stealth != nil && config.Stealth.Sleep != nil {
		delay = time.Duration(*config.Stealth.Sleep) * time.Millisecond
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

// loadTopPortsFromConfig loads the top ports configuration from the JSON file
func loadTopPortsFromConfig() ([]int, error) {
	resolver := utils.GetDefaultWordlistResolver()
	filePath := resolver.GetConfigFilePath("discover/port/top_ports.json")

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read top ports config: %w", err)
	}

	var config TopPortsConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse top ports config: %w", err)
	}

	return config.Ports, nil
}

// getTopNPorts returns the most commonly used TCP ports up to N ports
// Loads port data from configs/discover/port/top_ports.json configuration file
func getTopNPorts(n int) []int {
	// Use cached ports if available
	topPortsCacheLock.RLock()
	if len(topPortsCache) > 0 {
		topPortsCacheLock.RUnlock()
		return getTopNFromCache(n)
	}
	topPortsCacheLock.RUnlock()

	// Load ports from configuration file
	topPortsCacheLock.Lock()
	defer topPortsCacheLock.Unlock()

	// Double-check after acquiring write lock
	if len(topPortsCache) > 0 {
		return getTopNFromCache(n)
	}

	ports, err := loadTopPortsFromConfig()
	if err != nil {
		// Return empty cache and the getTopNFromCache function will handle the error
		topPortsCache = []int{}
		return []int{}
	}

	topPortsCache = ports

	return getTopNFromCache(n)
}

// getTopNFromCache returns the top N ports from the cached port list
func getTopNFromCache(n int) []int {
	if n <= len(topPortsCache) {
		result := make([]int, n)
		copy(result, topPortsCache[:n])
		return result
	}

	// For requests beyond our curated list, add ports sequentially
	result := make([]int, len(topPortsCache))
	copy(result, topPortsCache)

	used := make(map[int]bool)
	for _, p := range topPortsCache {
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
