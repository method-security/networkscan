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

// TopPortsConfig represents the simple JSON structure for port lists
type TopPortsConfig struct {
	Description string            `json:"description"`
	PortLists   map[string]string `json:"port_lists"`
}

var (
	topPortsConfig     *TopPortsConfig
	topPortsConfigLock sync.RWMutex
)

// getStealthPortScan performs a stealth port scan using native Go networking capabilities.
// It provides delay control and top-N port targeting for more covert scanning.
func getStealthPortScan(ctx context.Context, config discoverfern.DiscoverPortConfig) ([]*discoverfern.SocketDetails, error) {
	log := svc1log.FromContext(ctx)

	// Expand target hosts (handles CIDR ranges, IP ranges, and single hosts)
	targetHosts, err := utils.ParseTargetHosts(config.Target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target hosts: %w", err)
	}

	// Get stealth delay configuration (but don't calculate delay yet - do it per attempt)
	var sleepPtr, jitterPtr *int
	if config.Stealth != nil {
		sleepPtr = config.Stealth.Sleep
		jitterPtr = config.Stealth.Jitter
	}

	// Get target ports to scan
	targetPorts, err := getStealthTargetPorts(config)
	if err != nil {
		return nil, err
	}

	// Calculate initial delay for logging purposes
	initialDelay := utils.CalculateStealthDelay(sleepPtr, jitterPtr)

	log.Info("Starting stealth port scan",
		svc1log.SafeParam("target", config.Target),
		svc1log.SafeParam("hosts", len(targetHosts)),
		svc1log.SafeParam("ports", len(targetPorts)),
		svc1log.SafeParam("base_delay_ms", initialDelay.Milliseconds()))

	var allSocketDetails []*discoverfern.SocketDetails

	// Scan each host
	for _, host := range targetHosts {
		var openPorts []*discoverfern.PortDetails

		// Scan each port on this host with jittered delay
		for i, port := range targetPorts {
			if i > 0 || len(allSocketDetails) > 0 {
				// Calculate a new jittered delay for each attempt (skip first port of first host)
				delay := utils.CalculateStealthDelay(sleepPtr, jitterPtr)

				log.Debug("Applying stealth delay before scanning",
					svc1log.SafeParam("host", host),
					svc1log.SafeParam("port", port),
					svc1log.SafeParam("delay_ms", delay.Milliseconds()))

				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(delay):
				}
			}

			if isPortOpen(host, port) {
				openPorts = append(openPorts, &discoverfern.PortDetails{
					Port:     port,
					Protocol: common.TransportTypeTcp,
				})
				log.Debug("Found open port",
					svc1log.SafeParam("host", host),
					svc1log.SafeParam("port", port))
			}
		}

		socketDetails := &discoverfern.SocketDetails{
			Host:  host,
			Ip:    host, // For stealth scan, we'll use host as IP for simplicity
			Ports: openPorts,
		}

		allSocketDetails = append(allSocketDetails, socketDetails)
	}

	return allSocketDetails, nil
}

// getStealthTargetPorts determines which ports to scan based on the stealth configuration
func getStealthTargetPorts(config discoverfern.DiscoverPortConfig) ([]int, error) {
	var portString string

	// If specific ports are provided, use those
	if config.Ports != nil && *config.Ports != "" {
		portString = *config.Ports
	} else if config.TopPorts != nil {
		// Load port lists from JSON config
		portLists, err := getTopPortsConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to load port lists: %w", err)
		}

		// Use predefined port lists
		switch *config.TopPorts {
		case "10":
			if ports, ok := portLists["10"]; ok {
				portString = ports
			} else {
				return nil, fmt.Errorf("top-10 port list not found in config")
			}
		case "100":
			if ports, ok := portLists["100"]; ok {
				portString = ports
			} else {
				return nil, fmt.Errorf("top-100 port list not found in config")
			}
		case "1000":
			if ports, ok := portLists["1000"]; ok {
				portString = ports
			} else {
				return nil, fmt.Errorf("top-1000 port list not found in config")
			}
		case "full":
			if ports, ok := portLists["full"]; ok {
				portString = ports
			} else {
				portString = "1-65535" // Fallback
			}
		default:
			// Try to parse as number and map to closest predefined list
			if topN, err := strconv.Atoi(*config.TopPorts); err == nil {
				switch {
				case topN <= 10:
					if ports, ok := portLists["10"]; ok {
						portString = ports
					} else {
						return nil, fmt.Errorf("top-10 port list not found in config")
					}
				case topN <= 100:
					if ports, ok := portLists["100"]; ok {
						portString = ports
					} else {
						return nil, fmt.Errorf("top-100 port list not found in config")
					}
				case topN <= 1000:
					if ports, ok := portLists["1000"]; ok {
						portString = ports
					} else {
						return nil, fmt.Errorf("top-1000 port list not found in config")
					}
				default:
					if ports, ok := portLists["full"]; ok {
						portString = ports
					} else {
						portString = "1-65535" // Fallback
					}
				}
			} else {
				return nil, fmt.Errorf("invalid top-ports value: %s", *config.TopPorts)
			}
		}
	} else {
		// Default to top 100 ports for stealth
		portLists, err := getTopPortsConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to load port lists: %w", err)
		}
		if ports, ok := portLists["100"]; ok {
			portString = ports
		} else {
			return nil, fmt.Errorf("default top-100 port list not found in config")
		}
	}

	// Parse the port string into individual ports
	ports, err := parsePortList(portString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse port list: %w", err)
	}

	// Sort ports for consistent scanning order
	sort.Ints(ports)
	return ports, nil
}

// getTopPortsConfig loads and caches the top ports configuration
func getTopPortsConfig() (map[string]string, error) {
	// Check if already loaded
	topPortsConfigLock.RLock()
	if topPortsConfig != nil {
		defer topPortsConfigLock.RUnlock()
		return topPortsConfig.PortLists, nil
	}
	topPortsConfigLock.RUnlock()

	// Load the config
	topPortsConfigLock.Lock()
	defer topPortsConfigLock.Unlock()

	// Double-check after acquiring write lock
	if topPortsConfig != nil {
		return topPortsConfig.PortLists, nil
	}

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

	topPortsConfig = &config
	return topPortsConfig.PortLists, nil
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
func isPortOpen(host string, port int) bool {
	timeout := 3 * time.Second
	conn, err := net.DialTimeout("tcp", utils.FormatHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
