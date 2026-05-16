package cmd

import (
	// Standard
	"fmt"
	"strings"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	// Internal
	discover "github.com/Method-Security/networkscan/internal/discover"
	discoverhost "github.com/Method-Security/networkscan/internal/discover/host"
	discoverport "github.com/Method-Security/networkscan/internal/discover/port"
	discoverroute "github.com/Method-Security/networkscan/internal/discover/route"
	discoverservice "github.com/Method-Security/networkscan/internal/discover/service"
	"github.com/Method-Security/networkscan/utils"

	// External
	cobra "github.com/spf13/cobra"
)

// InitDiscoverCommand initializes the discover command and its subcommands (host, os, port, service, tls).
// Each subcommand implements a specific network discovery functionality.
func (a *NetworkScan) InitDiscoverCommand() {
	discoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover live hosts, open ports, running services, and TLS configurations on a network.",
		Long:  `Discover live hosts, open ports, running services, and TLS configurations on a network.`,
	}

	// Host Command
	discoverHostCmd := &cobra.Command{
		Use:   "host",
		Short: "Identify live hosts within a given IP, hostname, or CIDR range using various discovery techniques.",
		Long:  `Identify live hosts within a given IP, hostname, or CIDR range using various discovery techniques.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Target flags
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			var scanTypeEnum *discoverfern.HostScanType
			scanType, err := cmd.Flags().GetString("scan-type")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if scanType != "" {
				scanTypeEnumValue, err := discoverfern.NewHostScanTypeFromString(scanType)
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				scanTypeEnum = &scanTypeEnumValue
			}

			// Stealth flags - get these early for validation
			sleep, err := cmd.Flags().GetInt("sleep")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			jitter, err := cmd.Flags().GetInt("jitter")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if jitter > 0 && sleep == 0 {
				a.OutputSignal.AddError(fmt.Errorf("jitter parameter can only be used when sleep is also specified"))
				return
			}
			reverseLookup, err := cmd.Flags().GetBool("reverse-lookup")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Validate jitter range
			if jitter < 0 || jitter > 100 {
				a.OutputSignal.AddError(fmt.Errorf("jitter must be between 0 and 100 (percentage), got %d", jitter))
				return
			}

			// Set Config
			config := getDiscoverHostConfig(target, scanTypeEnum, sleep, jitter, reverseLookup)

			// Generate the report
			report, err := discoverhost.RunHostDiscovery(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverHostCmd.Flags().String("target", "", "Target IP address, hostname, or CIDR range to scan for live hosts")
	discoverHostCmd.Flags().String("scan-type", "ICMP_ECHO", "Discovery scan type: ICMP_ECHO, ICMP_TIMESTAMP, ARP, or ICMP_ADDRESS_MASK (not needed for stealth mode)")
	discoverHostCmd.Flags().Int("sleep", 0, "Sleep delay in seconds between hosts for stealth scan (stealth mode enabled when sleep > 0)")
	discoverHostCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to randomize sleep delay for stealth scan")
	discoverHostCmd.Flags().Bool("reverse-lookup", false, "Perform reverse DNS lookup sweep first to identify potential targets")

	// Mark Required Flags
	_ = discoverHostCmd.MarkFlagRequired("target")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverHostCmd)

	// Port Command
	discoverPortCmd := &cobra.Command{
		Use:   "port",
		Short: "Scan target hosts for open TCP ports using customizable scan types and port ranges.",
		Long:  `Scan target hosts for open TCP ports using customizable scan types and port ranges. Supports single IPs, hostnames, CIDR ranges, and IP ranges.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Target flags
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			ports, err := cmd.Flags().GetString("ports")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			topPorts, err := cmd.Flags().GetString("top-ports")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			packetsPerSecond, err := cmd.Flags().GetInt("packets-per-second")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			scanType, err := cmd.Flags().GetString("scan-type")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			scanTypeEnum, err := discoverfern.NewPortScanTypeFromString(scanType)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			validate, err := cmd.Flags().GetBool("validate")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			var validateAttemptTimeout *int
			var validateThreads *int
			var maxOpenPortsValidationThreshold *int
			if validate {
				// Validate attempt timeout
				validateAttemptTimeoutInt, err := cmd.Flags().GetInt("validate-attempt-timeout")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				validateAttemptTimeout = &validateAttemptTimeoutInt
				// Validate threads
				validateThreadsInt, err := cmd.Flags().GetInt("validate-threads")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				validateThreads = &validateThreadsInt
				maxOpenPortsValidationThresholdInt, err := cmd.Flags().GetInt("max-open-ports-validation-threshold")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				maxOpenPortsValidationThreshold = &maxOpenPortsValidationThresholdInt
			}

			// Stealth flags
			sleep, err := cmd.Flags().GetInt("sleep")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			jitter, err := cmd.Flags().GetInt("jitter")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if jitter > 0 && sleep == 0 {
				a.OutputSignal.AddError(fmt.Errorf("jitter parameter can only be used when sleep is also specified"))
				return
			}

			// Validate jitter range
			if jitter < 0 || jitter > 100 {
				a.OutputSignal.AddError(fmt.Errorf("jitter must be between 0 and 100 (percentage), got %d", jitter))
				return
			}

			// Set Config
			config := getDiscoverPortConfig(target, ports, topPorts, threads, packetsPerSecond, scanTypeEnum, validate, validateAttemptTimeout, validateThreads, maxOpenPortsValidationThreshold, sleep, jitter)

			// Generate the report
			report, err := discoverport.RunPortScan(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverPortCmd.Flags().String("target", "", "Target IP address, FQDN, CIDR range, or IP range to scan for open ports")
	discoverPortCmd.Flags().String("ports", "", "Comma-separated list or range of TCP ports to scan (e.g., 22,80,443 or 1-1024)")
	discoverPortCmd.Flags().String("top-ports", "", "Scan the top N most common TCP ports (options: full, 100, 1000)")
	discoverPortCmd.Flags().Int("threads", 25, "Number of concurrent threads to use during port scanning")
	discoverPortCmd.Flags().String("scan-type", "SYN", "Port scan type: SYN (default, requires root) or CONNECT")
	discoverPortCmd.Flags().Int("packets-per-second", 1000, "Packets per second to send (default: 1000)")
	discoverPortCmd.Flags().Bool("validate", false, "Validate open ports by using service detection techniques")
	discoverPortCmd.Flags().Int("validate-attempt-timeout", 10, "Timeout in seconds for each service detection attempt")
	discoverPortCmd.Flags().Int("validate-threads", 0, "Number of concurrent threads to use during service detection")
	discoverPortCmd.Flags().Int("max-open-ports-validation-threshold", 50, "Trigger validation warning when more than this many ports are open (default: 50)")
	discoverPortCmd.Flags().Int("sleep", 0, "Sleep delay in seconds between port scans for stealth scan (stealth mode enabled when sleep > 0)")
	discoverPortCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to randomize sleep delay for stealth scan")

	// Mark Required Flags
	_ = discoverPortCmd.MarkFlagRequired("target")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverPortCmd)

	discoverRouteCmd := &cobra.Command{
		Use:   "route",
		Short: "Perform traceroute to trace the network path to a target destination.",
		Long:  `Perform traceroute to trace the network path to a target destination using various probe types (UDP, ICMP, TCP SYN).`,
		Run: func(cmd *cobra.Command, args []string) {
			// Target flags
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			hostIP, err := cmd.Flags().GetString("host-ip")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			excludeTimeoutHops, err := cmd.Flags().GetBool("exclude-timeout-hops")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			probesPerHop, err := cmd.Flags().GetInt("probes-per-hop")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			probeDelay, err := cmd.Flags().GetInt("probe-delay")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			maxHops, err := cmd.Flags().GetInt("max-hops")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get probe type and validate
			probeTypeStr, err := cmd.Flags().GetString("probe-type")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			probeType, err := discoverfern.NewProbeTypeFromString(strings.ToUpper(probeTypeStr))
			if err != nil {
				a.OutputSignal.AddError(fmt.Errorf("invalid probe type: %s", probeTypeStr))
				return
			}

			// Get port and normalize
			port, err := cmd.Flags().GetInt("port")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if port == 0 && probeType != discoverfern.ProbeTypeIcmp {
				port = 33434 // Standard UDP traceroute port
			} else if probeType == discoverfern.ProbeTypeIcmp {
				port = 0 // ICMP doesn't use ports
			}

			// Set Config
			config := getDiscoverRouteConfig(targets, hostIP, excludeTimeoutHops, probesPerHop, probeDelay, maxHops, timeout, probeType, port)

			// Generate the report
			report, err := discoverroute.RunRouteDiscovery(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverRouteCmd.Flags().StringSlice("targets", []string{}, "Target IP addresses or hostnames to trace route to (comma-separated)")
	discoverRouteCmd.Flags().String("host-ip", "", "Host IP address for network interface binding")
	discoverRouteCmd.Flags().Bool("exclude-timeout-hops", false, "Exclude hops that timed out from the results")
	discoverRouteCmd.Flags().Int("probes-per-hop", 3, "Number of probes to send per hop (default: 3)")
	discoverRouteCmd.Flags().Int("probe-delay", 100, "Delay in milliseconds between probes (default: 100)")
	discoverRouteCmd.Flags().Int("max-hops", 30, "Maximum number of hops to trace (default: 30)")
	discoverRouteCmd.Flags().Int("timeout", 5, "Timeout in seconds for each probe (default: 5)")
	discoverRouteCmd.Flags().String("probe-type", "ICMP", "Probe packet type: UDP or ICMP (default: ICMP)")
	discoverRouteCmd.Flags().Int("port", 0, "Port number for UDP probes (default: 33434 for UDP)")

	// Mark Required Flags
	_ = discoverRouteCmd.MarkFlagRequired("targets")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverRouteCmd)

	// Service Command
	discoverServiceCmd := &cobra.Command{
		Use:   "service",
		Short: "Identify and fingerprint network services on a target host or specific port.",
		Long:  `Identify and fingerprint network services on a target host or specific port. Use --udp to scan common UDP ports.`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// UDP mode flag
			udp, err := cmd.Flags().GetBool("udp")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Validate target format based on UDP mode
			if !udp {
				// For TCP mode, target must include a port (IP:port or hostname:port)
				if !strings.Contains(target, ":") {
					a.OutputSignal.AddError(fmt.Errorf("target must include port for TCP mode (e.g., %s:80). Use --udp flag for UDP service discovery", target))
					return
				}
				// Use existing utility to validate the target format
				_, port := utils.ParseHostPort(target, 0)
				if port == 0 {
					a.OutputSignal.AddError(fmt.Errorf("target must include a valid port for TCP mode (e.g., %s:80). Use --udp flag for UDP service discovery", target))
					return
				}
			}

			// Stealth flags
			serviceType, err := cmd.Flags().GetString("service-type")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Fingerprintx timeout flag
			fingerprintxTimeout, err := cmd.Flags().GetInt("fingerprintx-timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set Config
			config, err := getDiscoverServiceConfig(target, timeout, serviceType, udp, fingerprintxTimeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate the report
			report, err := discoverservice.RunServiceFingerprint(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverServiceCmd.Flags().String("target", "", "Target address (IP:port or hostname:port for TCP, IP or hostname for UDP mode)")
	discoverServiceCmd.Flags().Int("timeout", 5, "Timeout in seconds for each service fingerprinting attempt")
	discoverServiceCmd.Flags().Int("fingerprintx-timeout", 0, "Timeout in seconds for fingerprintx attempt (default is no timeout)")
	discoverServiceCmd.Flags().Bool("udp", false, "Enable UDP service discovery mode (scans common UDP ports like DNS, NTP, SNMP, etc.)")
	discoverServiceCmd.Flags().String("service-type", "", "Service type to fingerprint for stealth mode: SSH, HTTP, GRPC, KERBEROS, LDAP, SMB (stealth mode enabled when specified)")

	// Mark Required Flags
	_ = discoverServiceCmd.MarkFlagRequired("target")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverServiceCmd)

	// TLS Command
	discoverTLSCmd := &cobra.Command{
		Use:   "tls",
		Short: "Retrieve and analyze the TLS configuration and certificate details for one or more target addresses.",
		Long:  `Retrieve and analyze the TLS configuration and certificate details for one or more target addresses.`,
		Run: func(cmd *cobra.Command, args []string) {
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			// Generate the config
			config := getDiscoverTLSConfig(targets, timeout)

			// Generate the report
			report, err := discover.GetTLSInfo(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverTLSCmd.Flags().StringSlice("targets", []string{}, "List of target addresses (IP:port or hostname:port) to analyze TLS configuration")
	discoverTLSCmd.Flags().Int("timeout", 30, "Timeout in seconds for each TLS handshake attempt")
	// Mark Required Flags
	_ = discoverTLSCmd.MarkFlagRequired("targets")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverTLSCmd)

	// Domain Command
	discoverDomainCmd := &cobra.Command{
		Use:   "domain",
		Short: "Discover domain information from a target host using LDAP/SMB discovery and DNS enumeration of domain controllers.",
		Long:  `Discover domain information from a target host using LDAP/SMB discovery and DNS enumeration of domain controllers.`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate the config
			config := getDiscoverDomainConfig(target)

			// Generate the report
			report, err := discover.RunDomainDiscovery(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverDomainCmd.Flags().String("target", "", "Target IP address or hostname to discover domain information from")

	// Mark Required Flags
	_ = discoverDomainCmd.MarkFlagRequired("target")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverDomainCmd)

	// Add Command to Root Command
	a.RootCmd.AddCommand(discoverCmd)
}

// getDiscoverPortConfig creates a configuration for port scanning with the provided parameters.
// It handles both specific port ranges and top ports scanning modes.
func getDiscoverPortConfig(target string, ports string, topPorts string, threads int, packetsPerSecond int, scanType discoverfern.PortScanType, validate bool, validateAttemptTimeout *int, validateThreads *int, maxOpenPortsValidationThreshold *int, sleep int, jitter int) discoverfern.DiscoverPortConfig {
	// Start with common fields that apply to both stealth and regular scans
	config := discoverfern.DiscoverPortConfig{
		Target:           target,
		Ports:            &ports,
		TopPorts:         &topPorts,
		PacketsPerSecond: packetsPerSecond,
	}

	if sleep > 0 || jitter > 0 {
		// Stealth mode - only set stealth-specific config
		stealthConfig := &discoverfern.PortStealthConfig{}
		if sleep > 0 {
			stealthConfig.Sleep = &sleep
		}
		if jitter > 0 {
			stealthConfig.Jitter = &jitter
		}
		config.Stealth = stealthConfig
	} else {
		// Regular scan mode - set naabu-specific config
		config.Threads = threads
		config.ScanType = scanType
		config.Validate = validate

		// Validation-related fields only apply to regular scans
		if validateAttemptTimeout != nil {
			config.ValidateAttemptTimeout = validateAttemptTimeout
		}
		if validateThreads != nil {
			config.ValidateThreads = validateThreads
		}
		if maxOpenPortsValidationThreshold != nil {
			threshold := max(0, *maxOpenPortsValidationThreshold)
			config.MaxOpenPortsValidationThreshold = &threshold
		}
	}

	return config
}

// getDiscoverRouteConfig creates a configuration for traceroute with the provided parameters.
// It sets up the targets, probe settings, and timing configurations.
func getDiscoverRouteConfig(targets []string, hostIP string, excludeTimeoutHops bool, probesPerHop, probeDelay, maxHops, timeout int, probeType discoverfern.ProbeType, port int) discoverfern.DiscoverRouteConfig {
	config := discoverfern.DiscoverRouteConfig{
		Targets:            targets,
		ExcludeTimeoutHops: excludeTimeoutHops,
		ProbesPerHop:       probesPerHop,
		ProbeDelay:         probeDelay,
		MaxHops:            maxHops,
		Timeout:            timeout,
		ProbeType:          probeType,
		Port:               port,
	}

	if hostIP != "" {
		config.HostIp = &hostIP
	}

	return config
}

// getDiscoverServiceConfig creates a configuration for service fingerprinting with the provided parameters.
// It sets up the target (in IP:port format for TCP, or just IP for UDP), timeout, UDP mode, and stealth-specific options.
func getDiscoverServiceConfig(target string, timeout int, serviceType string, udp bool, fingerprintxTimeout int) (discoverfern.DiscoverServiceConfig, error) {
	config := discoverfern.DiscoverServiceConfig{
		Target:              target,
		Timeout:             timeout,
		FingerprintxTimeout: fingerprintxTimeout,
	}
	if udp {
		config.Udp = &udp
	}
	if serviceType != "" {
		// Convert to uppercase for enum parsing
		serviceTypeEnum, err := discoverfern.NewStealthServiceTypeFromString(strings.ToUpper(serviceType))
		if err != nil {
			return config, fmt.Errorf("invalid service type '%s': %v", serviceType, err)
		}
		config.Stealth = &discoverfern.ServiceStealthConfig{
			ServiceType: serviceTypeEnum,
		}
	}
	return config, nil
}

// getDiscoverTLSConfig creates a configuration for TLS scanning with the provided parameters.
func getDiscoverTLSConfig(targets []string, timeout int) discoverfern.DiscoverTlsConfig {
	config := discoverfern.DiscoverTlsConfig{
		Targets: targets,
		Timeout: timeout,
	}
	return config
}

// getDiscoverHostConfig creates a configuration for host discovery with the provided parameters.
// It sets up the target, scan type, and stealth-specific options.
func getDiscoverHostConfig(target string, scanType *discoverfern.HostScanType, sleep int, jitter int, reverseLookup bool) discoverfern.DiscoverHostConfig {
	config := discoverfern.DiscoverHostConfig{
		Target: target,
	}

	// Check if stealth mode is enabled
	stealthEnabled := sleep > 0 || jitter > 0 || reverseLookup

	if stealthEnabled {
		// In stealth mode, configure stealth settings and don't set scanType
		stealthConfig := &discoverfern.HostStealthConfig{
			ReverseLookup: &reverseLookup,
		}
		if sleep > 0 {
			stealthConfig.Sleep = &sleep
		}
		if jitter > 0 {
			stealthConfig.Jitter = &jitter
		}
		config.Stealth = stealthConfig
	} else {
		// In non-stealth mode, set scanType if provided
		if scanType != nil {
			config.ScanType = scanType
		}
	}

	return config
}

// getDiscoverDomainConfig creates a configuration for domain discovery with the provided parameters.
// It sets up the target for domain discovery.
func getDiscoverDomainConfig(target string) discoverfern.DiscoverDomainConfig {
	return discoverfern.DiscoverDomainConfig{
		Target: target,
	}
}
