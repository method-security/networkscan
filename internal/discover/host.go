// Package discover implements network discovery functionality for finding live hosts and services.
package discover

import (
	// Standard
	"context"
	"fmt"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	// External
	goflags "github.com/projectdiscovery/goflags"
	result "github.com/projectdiscovery/naabu/v2/pkg/result"
	runner "github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// RunHostDiscovery performs host discovery on the specified target using the given scan type.
// It returns a report containing discovered hosts and any errors encountered during the process.
// The target can be a single IP, hostname, or CIDR range.
func RunHostDiscovery(ctx context.Context, target string, scantype discoverfern.HostScanType) (discoverfern.DiscoverHostReport, error) {
	errors := []string{}

	hostDiscoverResult, err := getHostDiscover(ctx, target, scantype)
	if err != nil {
		errors = append(errors, err.Error())
	}

	return discoverfern.DiscoverHostReport{
		Hosts:  hostDiscoverResult,
		Errors: errors,
	}, nil
}

// getHostDiscover configures and runs the host discovery process using the Naabu library.
// It sets up scan options based on the provided scan type and returns discovered host details.
func getHostDiscover(ctx context.Context, target string, scantype discoverfern.HostScanType) ([]*discoverfern.HostDetails, error) {
	hostDetails := []*discoverfern.HostDetails{}
	hostDiscoverOpts := &runner.Options{
		Silent:            true,
		JSON:              true,
		NoColor:           true,
		Retries:           3,
		WarmUpTime:        2,
		Rate:              1000,
		Threads:           25,
		PortThreshold:     0,
		StatsInterval:     5,
		Timeout:           runner.DefaultPortTimeoutSynScan,
		Host:              goflags.StringSlice{target},
		OnlyHostDiscovery: true,
		SkipHostDiscovery: false,
		InputReadTimeout:  3,
		ScanType:          "s",
		OnResult: func(hr *result.HostResult) {
			hostDetails = append(hostDetails, parseHostDiscoverResult(*hr))
		},
	}

	switch scantype {
	case discoverfern.HostScanTypeTcpSyn:
		hostDiscoverOpts.TcpSynPingProbes = goflags.StringSlice{"80"}
	case discoverfern.HostScanTypeTcpAck:
		hostDiscoverOpts.TcpAckPingProbes = goflags.StringSlice{"80"}
	case discoverfern.HostScanTypeIcmpEcho:
		hostDiscoverOpts.IcmpEchoRequestProbe = true
	case discoverfern.HostScanTypeIcmpTimestamp:
		hostDiscoverOpts.IcmpTimestampRequestProbe = true
	case discoverfern.HostScanTypeArp:
		hostDiscoverOpts.ArpPing = true
	case discoverfern.HostScanTypeIcmpAddressMask:
		hostDiscoverOpts.IcmpAddressMaskRequestProbe = true
	default:
		return hostDetails, fmt.Errorf("no valid scantype provided")
	}

	hostdiscover, err := runner.NewRunner(hostDiscoverOpts)
	if err != nil {
		return hostDetails, err
	}

	defer hostdiscover.Close()
	err = hostdiscover.RunEnumeration(ctx)
	if err != nil {
		return hostDetails, err
	}

	// Deduplicate hostDetails by Host and Ip
	unique := make(map[string]*discoverfern.HostDetails)
	for _, hd := range hostDetails {
		key := hd.Host + "|" + hd.Ip
		unique[key] = hd
	}
	result := make([]*discoverfern.HostDetails, 0, len(unique))
	for _, hd := range unique {
		result = append(result, hd)
	}

	return result, nil
}

// parseHostDiscoverResult converts a Naabu host result into our internal HostDetails format.
// It extracts the hostname and IP address from the discovery result.
func parseHostDiscoverResult(result result.HostResult) *discoverfern.HostDetails {
	return &discoverfern.HostDetails{
		Host: result.Host,
		Ip:   result.IP,
	}
}
