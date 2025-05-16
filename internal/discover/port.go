// Package port provides the data structures and logic necessary for interacting with ports on a network.
package discover

import (
	"context"

	discoverFern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

func getPortScan(ctx context.Context, target string, ports string, topports string, threads int, scantype string) ([]*discoverFern.HostScanDetails, error) {
	output := result.HostResult{}
	hosts := []*discoverFern.HostScanDetails{}
	// These settings mimic naabu's default settings
	portscanOpts := &runner.Options{
		Silent:            false,
		JSON:              true,
		NoColor:           true,
		Rate:              runner.DefaultRateConnectScan,
		Retries:           runner.DefaultRetriesConnectScan,
		Threads:           threads,
		Timeout:           runner.DefaultPortTimeoutConnectScan,
		Host:              goflags.StringSlice{target},
		SkipHostDiscovery: true,
		WarmUpTime:        2,
		InputReadTimeout:  180000000000, // This is their default
		OnResult: func(hr *result.HostResult) {
			output = *hr
			hosts = append(hosts, parsePortScanResult(&output))
		},
	}

	switch scantype {
	case "syn":
		portscanOpts.ScanType = runner.SynScan
	case "connect":
		portscanOpts.ScanType = runner.ConnectScan
	default:
		portscanOpts.ScanType = ""
	}

	if ports != "" {
		portscanOpts.Ports = ports
	}
	if topports != "" {
		portscanOpts.TopPorts = topports
	}

	portscan, err := runner.NewRunner(portscanOpts)
	if err != nil {
		return nil, err
	}

	defer portscan.Close()
	err = portscan.RunEnumeration(ctx)
	if err != nil {
		return nil, err
	}

	return hosts, nil

}

func parsePortScanResult(result *result.HostResult) *discoverFern.HostScanDetails {
	ports := []*discoverFern.PortScanDetails{}
	for _, p := range result.Ports {
		ports = append(ports, &discoverFern.PortScanDetails{
			Port:     p.Port,
			Protocol: p.Protocol.String(),
		})
	}
	host := discoverFern.HostScanDetails{
		Host:  result.Host,
		Ip:    result.IP,
		Ports: ports,
	}
	return &host
}

// RunPortScan takes a target host and a list of ports to scan and returns a report of all hosts that were scanned and
// their open ports.
func RunPortScan(ctx context.Context, target string, ports string, topport string, threads int, scantype string) (*discoverFern.PortScanReport, error) {
	resources := discoverFern.PortScanReport{}
	errors := []string{}

	portscanResult, err := getPortScan(ctx, target, ports, topport, threads, scantype)
	if err != nil {
		errors = append(errors, err.Error())
	}

	resources.Hosts = portscanResult
	resources.Errors = errors
	return &resources, nil
}
