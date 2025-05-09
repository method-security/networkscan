// Package host provides the data structures and logic necessary for interacting with hosts on a network.
package host

import (
	"context"
	"fmt"

	hostfern "github.com/Method-Security/networkscan/generated/go/host"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

func getHostDiscover(ctx context.Context, target string, scantype string) ([]*hostfern.HostDiscoverDetails, error) {
	hostDetails := []*hostfern.HostDiscoverDetails{}
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
			hostDetails = append(hostDetails, parseResult(*hr))
		},
	}

	switch scantype {
	case "tcpsyn":
		hostDiscoverOpts.TcpSynPingProbes = goflags.StringSlice{"80"}
	case "tcpack":
		hostDiscoverOpts.TcpAckPingProbes = goflags.StringSlice{"80"}
	case "icmpecho":
		hostDiscoverOpts.IcmpEchoRequestProbe = true
	case "icmptimestamp":
		hostDiscoverOpts.IcmpTimestampRequestProbe = true
	case "arp":
		hostDiscoverOpts.ArpPing = true
	case "icmpaddressmask":
		hostDiscoverOpts.IcmpAddressMaskRequestProbe = true
	default:
		fmt.Print("No valid scantype provided")
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

	return hostDetails, nil

}

func parseResult(result result.HostResult) *hostfern.HostDiscoverDetails {
	return &hostfern.HostDiscoverDetails{
		Host: result.Host,
		Ip:   result.IP,
	}
}

// RunHostDiscover takes a target host (which can be a CIDR) and a scantype and returns a report of all hosts that were discovered
func RunHostDiscover(ctx context.Context, target string, scantype string) (hostfern.HostDiscoverReport, error) {
	errors := []string{}

	hostDiscoverResult, err := getHostDiscover(ctx, target, scantype)
	if err != nil {
		errors = append(errors, err.Error())
	}

	return hostfern.HostDiscoverReport{
		Hosts:  hostDiscoverResult,
		Errors: errors,
	}, nil
}
