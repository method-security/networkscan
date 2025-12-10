package discover

import (
	// Standard
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	// Generated
	common "github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"

	// Internal
	"github.com/Method-Security/networkscan/utils"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	goflags "github.com/projectdiscovery/goflags"
	gologger "github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	result "github.com/projectdiscovery/naabu/v2/pkg/result"
	runner "github.com/projectdiscovery/naabu/v2/pkg/runner"
)

var requiredPorts = []string{
	"1",
	"2",
	"3",
	"9",
	"19",
	"32768",
	"32769",
	"32770",
	"49150",
	"49151",
	"49998",
	"49999",
	"52673",
	"52822",
	"52848",
	"52869",
	"54045",
	"54328",
	"55055",
	"55056",
	"55555",
	"55600",
	"56737",
	"56738",
	"57294",
	"57797",
	"58080",
	"54320",
	"54321",
	"60000",
	"60001",
	"61095",
	"61096",
	"61111",
	"62000",
	"65000",
	"65530",
	"65531",
	"65532",
	"65533",
	"65534",
	"65535",

	// --- Added 5 random ports per 5000-port chunk ---

	// 1–5000
	"487", "2399", "3728", "4441", "4983",

	// 5001–10000
	"5122", "6711", "8940", "9233", "9977",

	// 10001–15000
	"10344", "11988", "13201", "14492", "14933",

	// 15001–20000
	"15077", "16233", "17791", "18302", "19888",

	// 20001–25000
	"20044", "21491", "22337", "23988", "24812",

	// 25001–30000
	"25390", "26773", "27944", "28931", "29992",

	// 30001–35000
	"30011", "31672", "32777", "33902", "34881",

	// 35001–40000
	"35122", "36299", "37941", "38333", "39888",

	// 40001–45000
	"40155", "41777", "42991", "44002", "44833",

	// 45001–50000
	"45109", "46822", "47233", "49190", "49912",

	// 50001–55000
	"50177", "51988", "52611", "53992", "54841",

	// 55001–60000
	"55044", "56211", "57933", "58990", "59921",

	// 60001–65000
	"60077", "61123", "62394", "63988", "64821",
}

// stderrWriter implements writer.Writer interface to redirect all gologger output to stderr
type stderrWriter struct{}

func (s *stderrWriter) Write(data []byte, level levels.Level) {
	// Redirect all Naabu output to stderr instead of stdout
	_, _ = os.Stderr.Write(data)
}

// RunPortScan performs a port scan on the specified target using the provided configuration.
// It returns a report containing discovered open ports and any errors encountered during the process.
func RunPortScan(ctx context.Context, config discoverfern.DiscoverPortConfig) (*discoverfern.DiscoverPortReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Running port scan", svc1log.SafeParam("validate", config.Validate))

	// Ensure required ports are included in the scan if validation is enabled
	if config.Validate {
		config = ensureRequiredPorts(config, requiredPorts)
	}

	var portscanResult []*discoverfern.SocketDetails
	var err error

	if config.Stealth != nil {
		portscanResult, err = getStealthPortScan(ctx, config)
	} else {
		portscanResult, err = getPortScan(ctx, config)
	}
	if err != nil {
		errors = append(errors, err.Error())
	}

	// Filter ports by service validation if requested
	if config.Validate {
		// Check if either of the required ports are open
		if !hasOpenRequiredPorts(portscanResult, requiredPorts) {
			log.Info("Required validation ports are closed, skipping validation", svc1log.SafeParam("requiredPorts", requiredPorts))
			// Required ports are not open, consider everything validated (skip validation)
			return &discoverfern.DiscoverPortReport{
				Config: &config, Result: &discoverfern.DiscoverPortResult{Sockets: portscanResult}, Errors: errors}, nil
		}
		log.Info("Required validation ports are open, proceeding with validation", svc1log.SafeParam("requiredPorts", requiredPorts))

		// Required ports are open, proceed with validation
		validatedPorts, validationErrors := validatePortScan(ctx, config, portscanResult)
		portscanResult = validatedPorts
		errors = append(errors, validationErrors...)
	}

	return &discoverfern.DiscoverPortReport{
		Config: &config, Result: &discoverfern.DiscoverPortResult{Sockets: portscanResult}, Errors: errors}, nil
}

// getPortScan configures and runs the port scanning process using the Naabu library.
// It sets up scan options based on the provided configuration and returns discovered port details.
func getPortScan(ctx context.Context, config discoverfern.DiscoverPortConfig) ([]*discoverfern.SocketDetails, error) {
	// Hide OS args from Naabu
	hideOsArgsFromNaabu()

	// Temporarily redirect gologger output to stderr to prevent Naabu stdout pollution
	originalWriter := writer.NewCLI() // Create a new CLI writer to restore later
	gologger.DefaultLogger.SetWriter(&stderrWriter{})

	// Parse target hosts and create IP-to-hostname mapping
	targetHosts, ipToHostname, err := utils.ParseTargetHostsWithMapping(config.Target)
	if err != nil {
		// Restore original gologger writer before returning error
		gologger.DefaultLogger.SetWriter(originalWriter)
		return nil, fmt.Errorf("failed to parse target hosts: %w", err)
	}

	output := result.HostResult{}
	hosts := []*discoverfern.SocketDetails{}
	// These settings mimic naabu's default settings with hardcoded slower rate
	portscanOpts := &runner.Options{
		Silent:            false,
		JSON:              true,
		NoColor:           true,
		Verbose:           false,
		Debug:             false,
		Stream:            false,
		Rate:              config.PacketsPerSecond, // Global rate limit: packets per second across all threads (this is the bottleneck, not thread count)
		Retries:           runner.DefaultRetriesConnectScan,
		Threads:           config.Threads,
		Timeout:           runner.DefaultPortTimeoutConnectScan,
		Host:              goflags.StringSlice(targetHosts), // Use resolved IPs
		SkipHostDiscovery: true,
		WarmUpTime:        2,
		InputReadTimeout:  180000000000, // This is their default
		// Output:            "/dev/null",  // Redirect all output to null
		OnResult: func(hr *result.HostResult) {
			output = *hr
			hosts = append(hosts, parsePortScanResult(&output, ipToHostname))
		},
	}

	switch config.ScanType {
	case discoverfern.PortScanTypeSyn:
		portscanOpts.ScanType = runner.SynScan
	case discoverfern.PortScanTypeConnect:
		portscanOpts.ScanType = runner.ConnectScan
	}

	if config.Ports != nil {
		portscanOpts.Ports = *config.Ports
	}

	if config.TopPorts != nil {
		portscanOpts.TopPorts = *config.TopPorts
	}

	portscan, err := runner.NewRunner(portscanOpts)
	if err != nil {
		return nil, err
	}

	err = portscan.RunEnumeration(ctx)
	if err != nil {
		// Restore original gologger writer before returning error
		gologger.DefaultLogger.SetWriter(originalWriter)
		return nil, err
	}

	defer portscan.Close()

	// Restore original gologger writer
	gologger.DefaultLogger.SetWriter(originalWriter)

	return hosts, nil

}

// parsePortScanResult converts a Naabu port scan result into our internal SocketDetails format.
// It extracts host information and open ports from the scan result.
// If the IP was resolved from a hostname, it uses the original hostname as the host field.
func parsePortScanResult(result *result.HostResult, ipToHostname map[string]string) *discoverfern.SocketDetails {
	ports := []*discoverfern.PortDetails{}
	for _, p := range result.Ports {
		ports = append(ports, &discoverfern.PortDetails{
			Port:     p.Port,
			Protocol: common.TransportType(p.Protocol.String()),
		})
	}

	// Use original hostname if available, otherwise use the IP as host
	hostField := result.IP
	if originalHostname, exists := ipToHostname[result.IP]; exists {
		hostField = originalHostname
	}

	host := discoverfern.SocketDetails{
		Host:  hostField,
		Ip:    result.IP,
		Ports: ports,
	}
	return &host
}

// ensureRequiredPorts modifies the scan configuration to include required ports
func ensureRequiredPorts(config discoverfern.DiscoverPortConfig, requiredPorts []string) discoverfern.DiscoverPortConfig {
	// If specific ports are already configured, add required ports to them
	if config.Ports != nil && *config.Ports != "" {
		existingPorts := *config.Ports
		for _, port := range requiredPorts {
			if !strings.Contains(existingPorts, port) {
				existingPorts += "," + port
			}
		}
		config.Ports = &existingPorts
	} else if config.TopPorts != nil {
		// If using top ports, we need to switch to specific ports that include required ports
		requiredPortsStr := ""
		for i, port := range requiredPorts {
			if i > 0 {
				requiredPortsStr += ","
			}
			requiredPortsStr += port
		}
		config.Ports = &requiredPortsStr
		// Keep TopPorts as well, naabu will scan both
	} else {
		// No specific ports configured, add required ports
		requiredPortsStr := ""
		for i, port := range requiredPorts {
			if i > 0 {
				requiredPortsStr += ","
			}
			requiredPortsStr += port
		}
		config.Ports = &requiredPortsStr
	}

	return config
}

// hasOpenRequiredPorts checks if any of the required ports (as strings) are open in the scan results
func hasOpenRequiredPorts(scanResults []*discoverfern.SocketDetails, requiredPorts []string) bool {
	requiredPortsMap := make(map[string]bool)
	for _, port := range requiredPorts {
		requiredPortsMap[port] = true
	}

	for _, socket := range scanResults {
		if socket != nil && socket.Ports != nil {
			for _, port := range socket.Ports {
				if port != nil && requiredPortsMap[strconv.Itoa(port.Port)] {
					return true
				}
			}
		}
	}

	return false
}

// hideOsArgsFromNaabu prevents Naabu from processing command line arguments.
// This is necessary because Naabu tries to parse all command line arguments, which can conflict with our CLI.
func hideOsArgsFromNaabu() {
	orig := make([]string, len(os.Args))
	copy(orig, os.Args)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = os.Args[:1]
}
