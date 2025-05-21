package discover

import (
	"context"
	"strings"

	discoverFern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// RunPortScan takes a target host and a list of ports to scan and returns a report of all hosts that were scanned and
// their open ports.
func RunPortScan(ctx context.Context, config discoverFern.DiscoverPortConfig) (*discoverFern.DiscoverPortReport, error) {
	resources := discoverFern.DiscoverPortReport{Config: &config}
	errors := []string{}

	portscanResult, err := getPortScan(ctx, config)
	if err != nil {
		errors = append(errors, err.Error())
	}

	resources.Hosts = portscanResult
	resources.Errors = errors
	return &resources, nil
}

func getPortScan(ctx context.Context, config discoverFern.DiscoverPortConfig) ([]*discoverFern.SocketDetails, error) {
	output := result.HostResult{}
	hosts := []*discoverFern.SocketDetails{}
	// These settings mimic naabu's default settings
	portscanOpts := &runner.Options{
		Silent:            false,
		JSON:              true,
		NoColor:           true,
		Rate:              runner.DefaultRateConnectScan,
		Retries:           runner.DefaultRetriesConnectScan,
		Threads:           config.Threads,
		Timeout:           runner.DefaultPortTimeoutConnectScan,
		Host:              goflags.StringSlice{config.Target},
		SkipHostDiscovery: true,
		WarmUpTime:        2,
		InputReadTimeout:  180000000000, // This is their default
		OnResult: func(hr *result.HostResult) {
			output = *hr
			hosts = append(hosts, parsePortScanResult(&output))
		},
	}

	switch config.ScanType {
	case "syn":
		portscanOpts.ScanType = runner.SynScan
	case "connect":
		portscanOpts.ScanType = runner.ConnectScan
	}

	// Combine tcpPorts and udpPorts into a single string for portscanOpts.Ports
	var portList []string
	if config.TcpPorts != nil {
		portList = append(portList, *config.TcpPorts)
	}
	if config.UdpPorts != nil {
		udpParts := strings.Split(*config.UdpPorts, ",")
		for _, udp := range udpParts {
			udp = strings.TrimSpace(udp)
			if udp != "" {
				portList = append(portList, "u:"+udp)
			}
		}
	}
	if len(portList) > 0 {
		portscanOpts.Ports = strings.Join(portList, ",")
	}

	if config.TopPorts != nil {
		portscanOpts.TopPorts = *config.TopPorts
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

func parsePortScanResult(result *result.HostResult) *discoverFern.SocketDetails {
	ports := []*discoverFern.PortDetails{}
	for _, p := range result.Ports {
		ports = append(ports, &discoverFern.PortDetails{
			Port:     p.Port,
			Protocol: p.Protocol.String(),
		})
	}
	host := discoverFern.SocketDetails{
		Host:  result.Host,
		Ip:    result.IP,
		Ports: ports,
	}
	return &host
}
