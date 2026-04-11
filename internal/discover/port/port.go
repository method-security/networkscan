//go:build !androidcompat

package discover

import (
	// Standard
	"context"
	"flag"
	"fmt"
	"os"
	"sync"

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

	// Port validation checks:
	// 1. Check if open ports exceed threshold
	// 2. Check if required validation ports are open
	if config.Validate {
		shouldValidate := false

		// Step 1: Check if the number of open ports exceeds the validation threshold
		if config.MaxOpenPortsValidationThreshold != nil && *config.MaxOpenPortsValidationThreshold > 0 {
			openPortCount := countOpenPorts(portscanResult)
			if openPortCount > *config.MaxOpenPortsValidationThreshold {
				log.Warn("Number of open ports exceeds validation threshold, triggering validation",
					svc1log.SafeParam("openPorts", openPortCount),
					svc1log.SafeParam("threshold", *config.MaxOpenPortsValidationThreshold))
				errors = append(errors, fmt.Sprintf("validation triggered due to count of open ports exceeding threshold (%d > %d)", openPortCount, *config.MaxOpenPortsValidationThreshold)) // Note: DD Metrics is generated off of this error line. Please update with caution
				shouldValidate = true
			}
		}
		// Step 2: Check if required validation ports are open
		hasOpen := hasOpenRequiredPorts(portscanResult, requiredPorts)
		if hasOpen {
			log.Warn("Required validation ports are open, triggering validation", svc1log.SafeParam("requiredPorts", requiredPorts))
			errors = append(errors, fmt.Sprintf("validation triggered due to one or more validation ports being open: %v", requiredPorts)) // Note: DD Metrics is generated off of this error line. Please update with caution
			shouldValidate = true
		}

		// If neither condition is met, skip validation
		if !shouldValidate {
			log.Info("Skipping validation, conditions not met")
			return &discoverfern.DiscoverPortReport{
				Config: &config, Result: &discoverfern.DiscoverPortResult{Sockets: portscanResult}, Errors: errors}, nil
		}

		// If either condition is met, proceed with validation
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
	restoreArgs := hideOsArgsFromNaabu()
	defer restoreArgs()

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

	// Detect IP versions present in targets
	ipVersions := utils.DetectIPVersions(targetHosts)

	var mu sync.Mutex
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
		IPVersion:         goflags.StringSlice(ipVersions),
		SkipHostDiscovery: true,
		WarmUpTime:        2,
		InputReadTimeout:  180000000000, // This is their default
		OnResult: func(hr *result.HostResult) {
			mu.Lock()
			output = *hr
			hosts = append(hosts, parsePortScanResult(&output, ipToHostname))
			mu.Unlock()
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

// hideOsArgsFromNaabu prevents Naabu from processing command line arguments.
// This is necessary because Naabu tries to parse all command line arguments, which can conflict with our CLI.
// It returns a restore function that must be called after naabu init to restore the original os.Args.
func hideOsArgsFromNaabu() func() {
	orig := make([]string, len(os.Args))
	copy(orig, os.Args)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = os.Args[:1]
	return func() { os.Args = orig }
}
