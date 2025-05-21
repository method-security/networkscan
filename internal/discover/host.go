package discover

import (
	"context"
	"fmt"

	discoverFern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// RunHostDiscovery takes a target host (which can be a CIDR) and a scantype and returns a report of all hosts that were discovered
func RunHostDiscovery(ctx context.Context, target string, scantype discoverFern.HostScanType) (discoverFern.DiscoverHostReport, error) {
	errors := []string{}

	hostDiscoverResult, err := getHostDiscover(ctx, target, scantype)
	if err != nil {
		errors = append(errors, err.Error())
	}

	return discoverFern.DiscoverHostReport{
		Hosts:  hostDiscoverResult,
		Errors: errors,
	}, nil
}

func getHostDiscover(ctx context.Context, target string, scantype discoverFern.HostScanType) ([]*discoverFern.HostDetails, error) {
	hostDetails := []*discoverFern.HostDetails{}
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
	case discoverFern.HostScanTypeTcpSyn:
		hostDiscoverOpts.TcpSynPingProbes = goflags.StringSlice{"80"}
	case discoverFern.HostScanTypeTcpAck:
		hostDiscoverOpts.TcpAckPingProbes = goflags.StringSlice{"80"}
	case discoverFern.HostScanTypeIcmpEcho:
		hostDiscoverOpts.IcmpEchoRequestProbe = true
	case discoverFern.HostScanTypeIcmpTimestamp:
		hostDiscoverOpts.IcmpTimestampRequestProbe = true
	case discoverFern.HostScanTypeArp:
		hostDiscoverOpts.ArpPing = true
	case discoverFern.HostScanTypeIcmpAddressMask:
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
	unique := make(map[string]*discoverFern.HostDetails)
	for _, hd := range hostDetails {
		key := hd.Host + "|" + hd.Ip
		unique[key] = hd
	}
	result := make([]*discoverFern.HostDetails, 0, len(unique))
	for _, hd := range unique {
		result = append(result, hd)
	}

	return result, nil
}

func parseHostDiscoverResult(result result.HostResult) *discoverFern.HostDetails {
	return &discoverFern.HostDetails{
		Host: result.Host,
		Ip:   result.IP,
	}
}
