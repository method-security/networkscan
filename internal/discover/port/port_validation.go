package discover

import (
	"strconv"
	"strings"

	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

// requiredPorts are added to every scan when Validate is true.
// If any of these ports appear open, it signals that the target may be a canary/honeypot
// and triggers the full validation pass.
var requiredPorts = []string{
	"1",
	"2",
	"4873",
	"9127",
	"10439",
	"15872",
	"21345",
	"27654",
	"31987",
	"35841",
	"40129",
	"44762",
	"48991",
	"51234",
	"54321",
	"57689",
	"60321",
	"62844",
	"64998",
	"65535",
}

// ensureRequiredPorts modifies the scan configuration to include required ports.
func ensureRequiredPorts(config discoverfern.DiscoverPortConfig, required []string) discoverfern.DiscoverPortConfig {
	requiredStr := strings.Join(required, ",")
	if config.Ports != nil && *config.Ports != "" {
		existing := *config.Ports
		for _, port := range required {
			if !strings.Contains(existing, port) {
				existing += "," + port
			}
		}
		config.Ports = &existing
	} else if config.TopPorts != nil {
		// Keep TopPorts set so the full top-N scan still runs; add required ports
		// separately so both are scanned (naabu merges Ports + TopPorts).
		config.Ports = &requiredStr
	} else {
		config.Ports = &requiredStr
	}
	return config
}

// hasOpenRequiredPorts returns true if any required port (by string value) is open in the results.
func hasOpenRequiredPorts(scanResults []*discoverfern.SocketDetails, required []string) bool {
	requiredMap := make(map[string]bool, len(required))
	for _, p := range required {
		requiredMap[p] = true
	}
	for _, socket := range scanResults {
		if socket == nil {
			continue
		}
		for _, port := range socket.Ports {
			if port != nil && requiredMap[strconv.Itoa(port.Port)] {
				return true
			}
		}
	}
	return false
}

// countOpenPorts returns the total number of open ports across all hosts.
func countOpenPorts(scanResults []*discoverfern.SocketDetails) int {
	count := 0
	for _, socket := range scanResults {
		if socket != nil {
			count += len(socket.Ports)
		}
	}
	return count
}
