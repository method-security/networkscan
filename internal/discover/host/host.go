// Package discover implements network discovery functionality for finding live hosts and services.
package discover

import (
	// Standard
	"context"
	"fmt"
	"os"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	// External
	goflags "github.com/projectdiscovery/goflags"
	gologger "github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	result "github.com/projectdiscovery/naabu/v2/pkg/result"
	runner "github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// stderrWriter implements writer.Writer interface to redirect all gologger output to stderr
type stderrWriter struct{}

func (s *stderrWriter) Write(data []byte, level levels.Level) {
	// Redirect all Naabu output to stderr instead of stdout
	_, _ = os.Stderr.Write(data)
}

// RunHostDiscovery performs host discovery on the specified target using the provided configuration.
// It returns a report containing discovered hosts and any errors encountered during the process.
// The target can be a single IP, hostname, or CIDR range.
func RunHostDiscovery(ctx context.Context, config discoverfern.DiscoverHostConfig) (*discoverfern.DiscoverHostReport, error) {
	errors := []string{}

	var hostDiscoverResult []*discoverfern.HostDetails
	var err error

	if config.Stealth != nil {
		hostDiscoverResult, err = getStealthHostDiscovery(ctx, config)
	} else if config.ScanType != nil {
		hostDiscoverResult, err = getHostDiscover(ctx, config.Target, *config.ScanType)
	} else {
		return nil, fmt.Errorf("either scan-type or stealth mode must be specified")
	}

	if err != nil {
		errors = append(errors, err.Error())
	}

	return &discoverfern.DiscoverHostReport{
		Config: &config,
		Result: &discoverfern.DiscoverHostResult{Hosts: hostDiscoverResult},
		Errors: errors,
	}, nil
}

// getHostDiscover configures and runs the host discovery process using the Naabu library.
// It sets up scan options based on the provided scan type and returns discovered host details.
func getHostDiscover(ctx context.Context, target string, scantype discoverfern.HostScanType) ([]*discoverfern.HostDetails, error) {
	// Temporarily redirect gologger output to stderr to prevent Naabu stdout pollution
	originalWriter := writer.NewCLI() // Create a new CLI writer to restore later
	gologger.DefaultLogger.SetWriter(&stderrWriter{})

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
		// Explicitly disable all probe types to prevent Naabu from enabling defaults
		// When no probes are specified, Naabu automatically enables multiple probe types
		// including ICMP Echo, ICMP Timestamp, and TCP probes on ports 80/443.
		// We explicitly disable all probe types here and only enable the requested one.
		IcmpEchoRequestProbe:        false,
		IcmpTimestampRequestProbe:   false,
		IcmpAddressMaskRequestProbe: false,
		ArpPing:                     false,
		IPv6NeighborDiscoveryPing:   false,
	}

	switch scantype {
	case discoverfern.HostScanTypeIcmpEcho:
		hostDiscoverOpts.IcmpEchoRequestProbe = true
	case discoverfern.HostScanTypeIcmpTimestamp:
		hostDiscoverOpts.IcmpTimestampRequestProbe = true
	case discoverfern.HostScanTypeArp:
		hostDiscoverOpts.ArpPing = true
	case discoverfern.HostScanTypeIcmpAddressMask:
		hostDiscoverOpts.IcmpAddressMaskRequestProbe = true
	default:
		// Restore original gologger writer before returning error
		gologger.DefaultLogger.SetWriter(originalWriter)
		return hostDetails, fmt.Errorf("no valid scantype provided")
	}

	hostdiscover, err := runner.NewRunner(hostDiscoverOpts)
	if err != nil {
		// Restore original gologger writer before returning error
		gologger.DefaultLogger.SetWriter(originalWriter)
		return hostDetails, err
	}

	err = hostdiscover.RunEnumeration(ctx)
	if err != nil {
		// Restore original gologger writer before returning error
		gologger.DefaultLogger.SetWriter(originalWriter)
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

	defer hostdiscover.Close()

	// Restore original gologger writer
	gologger.DefaultLogger.SetWriter(originalWriter)

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
