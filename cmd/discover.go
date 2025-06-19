package cmd

import (
	// Standard
	"errors"
	"os/exec"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	// Internal
	discover "github.com/Method-Security/networkscan/internal/discover"
	// External
	privileges "github.com/projectdiscovery/naabu/v2/pkg/privileges"
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

	discoverHostCmd := &cobra.Command{
		Use:   "host",
		Short: "Identify live hosts within a given IP, hostname, or CIDR range using various discovery techniques.",
		Long:  `Identify live hosts within a given IP, hostname, or CIDR range using various discovery techniques.`,
		Run: func(cmd *cobra.Command, args []string) {
			if !privileges.IsPrivileged {
				a.OutputSignal.AddError(errors.New("discover host can only be run as a privileged user"))
				return
			}

			// Target flags
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			scanType, err := cmd.Flags().GetString("scan-type")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			scanTypeEnum, err := discoverfern.NewHostScanTypeFromString(scanType)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate the report
			report, err := discover.RunHostDiscovery(cmd.Context(), target, scanTypeEnum)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverHostCmd.Flags().String("target", "", "Target IP address, hostname, or CIDR range to scan for live hosts")
	discoverHostCmd.Flags().String("scan-type", "ICMP_ECHO", "Discovery scan type: TCP_SYN, TCP_ACK, ICMP_ECHO, ICMP_TIMESTAMP, ARP, or ICMP_ADDRESS_MASK")

	// Mark Required Flags
	_ = discoverHostCmd.MarkFlagRequired("target")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverHostCmd)

	discoverOSCmd := &cobra.Command{
		Use:   "os",
		Short: "Detect and fingerprint the operating system running on a specified host (requires nmap and root privileges).",
		Long:  `Detect and fingerprint the operating system running on a specified host (requires nmap and root privileges).`,
		Run: func(cmd *cobra.Command, args []string) {
			if !privileges.IsPrivileged {
				a.OutputSignal.AddError(errors.New("discover os can only be run as a privileged user"))
				return
			}

			// Check if nmap is installed
			_, err := exec.LookPath("nmap")
			if err != nil {
				a.OutputSignal.AddError(errors.New("nmap is not installed or is not in the system path"))
				return
			}

			// Target flags
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate the report
			report, err := discover.RunOsFingerprint(cmd.Context(), target)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverOSCmd.Flags().String("target", "", "Target IP address or fully qualified domain name (FQDN) for OS fingerprinting")

	// Mark Required Flags
	_ = discoverOSCmd.MarkFlagRequired("target")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverOSCmd)

	discoverPortCmd := &cobra.Command{
		Use:   "port",
		Short: "Scan a target host for open TCP ports using customizable scan types and port ranges.",
		Long:  `Scan a target host for open TCP ports using customizable scan types and port ranges.`,
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

			// Set Config
			config := getDiscoverPortConfig(target, ports, topPorts, threads, scanTypeEnum)

			// Generate the report
			report, err := discover.RunPortScan(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverPortCmd.Flags().String("target", "", "Target IP address or FQDN to scan for open ports")
	discoverPortCmd.Flags().String("ports", "", "Comma-separated list or range of TCP ports to scan (e.g., 22,80,443 or 1-1024)")
	discoverPortCmd.Flags().String("top-ports", "", "Scan the top N most common TCP ports (options: full, 100, 1000)")
	discoverPortCmd.Flags().Int("threads", 25, "Number of concurrent threads to use during port scanning")
	discoverPortCmd.Flags().String("scan-type", "SYN", "Port scan type: SYN (default, requires root) or CONNECT")

	// Mark Required Flags
	_ = discoverPortCmd.MarkFlagRequired("target")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverPortCmd)

	discoverServiceCmd := &cobra.Command{
		Use:   "service",
		Short: "Identify and fingerprint the network service running on a specific open port of a target host.",
		Long:  `Identify and fingerprint the network service running on a specific open port of a target host.`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			port, err := cmd.Flags().GetInt("port")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set Config
			config := getDiscoverServiceConfig(target, port, timeout)

			// Generate the report
			report, err := discover.RunServiceFingerprint(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverServiceCmd.Flags().String("target", "", "Target IP address or hostname where the service is running")
	discoverServiceCmd.Flags().Int("port", 0, "Port number of the service to fingerprint (e.g., 443)")
	discoverServiceCmd.Flags().Int("timeout", 5, "Timeout in seconds for each service fingerprinting attempt")

	// Mark Required Flags
	_ = discoverServiceCmd.MarkFlagRequired("target")
	_ = discoverServiceCmd.MarkFlagRequired("port")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverServiceCmd)

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
			verifyTLS, err := cmd.Flags().GetBool("verify-tls")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate the config
			config := getDiscoverTLSConfig(targets, timeout, verifyTLS)

			// Generate the report
			report, err := discover.GetTLSInfo(cmd.Context(), targets, config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverTLSCmd.Flags().StringSlice("targets", []string{}, "List of target addresses (IP:port or hostname:port) to analyze TLS configuration")
	discoverTLSCmd.Flags().Int("timeout", 30, "Timeout in seconds for each TLS handshake attempt")
	discoverTLSCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates (default: true)")

	// Mark Required Flags
	_ = discoverTLSCmd.MarkFlagRequired("targets")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverTLSCmd)

	// Add Command to Root Command
	a.RootCmd.AddCommand(discoverCmd)
}

// getDiscoverPortConfig creates a configuration for port scanning with the provided parameters.
// It handles both specific port ranges and top ports scanning modes.
func getDiscoverPortConfig(target string, ports string, topPorts string, threads int, scanType discoverfern.PortScanType) discoverfern.DiscoverPortConfig {
	return discoverfern.DiscoverPortConfig{
		Target:   target,
		Ports:    &ports,
		TopPorts: &topPorts,
		Threads:  &threads,
		ScanType: &scanType,
	}
}

// getDiscoverServiceConfig creates a configuration for service fingerprinting with the provided parameters.
// It sets up the target, port, and timeout for service discovery.
func getDiscoverServiceConfig(target string, port int, timeout int) discoverfern.DiscoverServiceConfig {
	return discoverfern.DiscoverServiceConfig{
		Target:  target,
		Port:    port,
		Timeout: &timeout,
	}
}

// getDiscoverTLSConfig creates a configuration for TLS scanning with the provided parameters.
// It configures the targets, timeout, and TLS verification settings.
func getDiscoverTLSConfig(targets []string, timeout int, verifyTLS bool) discoverfern.DiscoverTlsConfig {
	config := discoverfern.DiscoverTlsConfig{
		Targets:   targets,
		Timeout:   &timeout,
		VerifyTls: &verifyTLS,
	}
	return config
}
