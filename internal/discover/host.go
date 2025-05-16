package discover

import (
	"context"
	"fmt"

	discoverFern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// RunHostDiscover takes a target host (which can be a CIDR) and a scantype and returns a report of all hosts that were discovered
func RunHostDiscovery(ctx context.Context, target string, scantype string) (discoverFern.DiscoverHostReport, error) {
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

func getHostDiscover(ctx context.Context, target string, scantype string) ([]*discoverFern.DiscoverHostDetails, error) {
	hostDetails := []*discoverFern.DiscoverHostDetails{}
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

func parseHostDiscoverResult(result result.HostResult) *discoverFern.DiscoverHostDetails {
	return &discoverFern.DiscoverHostDetails{
		Host: result.Host,
		Ip:   result.IP,
	}
}
