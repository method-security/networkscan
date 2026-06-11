package service

import (
	"testing"

	plugins "github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

func TestFingerprintxUDPPortsCoverRegisteredUDPPluginPriorities(t *testing.T) {
	configuredPorts := make(map[int]struct{})
	for _, port := range fingerprintxUDPPorts() {
		configuredPorts[port] = struct{}{}
	}

	priorityPorts := make(map[int]struct{})
	for _, plugin := range plugins.Plugins[plugins.UDP] {
		for port := 1; port <= 65535; port++ {
			if plugin.PortPriority(uint16(port)) {
				priorityPorts[port] = struct{}{}
				if _, ok := configuredPorts[port]; !ok {
					t.Fatalf("fingerprintx UDP plugin %s prioritizes port %d, but fingerprintxUDPPorts does not include it", plugin.Name(), port)
				}
			}
		}
	}

	for port := range configuredPorts {
		if _, ok := priorityPorts[port]; !ok {
			t.Fatalf("fingerprintxUDPPorts includes port %d, but no registered fingerprintx UDP plugin prioritizes it", port)
		}
	}
}
