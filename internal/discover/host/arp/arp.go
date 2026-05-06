// Package arp reads the host's ARP neighbor cache using platform-specific
// Go packages — no external processes are spawned on any supported platform.
package arp

import (
	// Standard
	"context"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"

	// Internal
	operatingsystem "github.com/Method-Security/networkscan/internal/discover/host/arp/operatingsystem"
)

// RunHostArpTable reads the host's ARP table and returns a structured report.
// The underlying read is delegated to the platform-specific implementation in
// the operating_systems package (linux / darwin / windows).
func RunHostArpTable(_ context.Context, config discoverfern.DiscoverHostArpConfig) (*discoverfern.DiscoverHostArpReport, error) {
	errors := []string{}

	interfaces, err := operatingsystem.GetArpEntries()
	if err != nil {
		errors = append(errors, err.Error())
	}

	return &discoverfern.DiscoverHostArpReport{
		Config: &config,
		Result: &discoverfern.DiscoverHostArpResult{Interfaces: interfaces},
		Errors: errors,
	}, nil
}
