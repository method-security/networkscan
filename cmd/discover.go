package cmd

import (
	"errors"
	"os/exec"

	discoverFern "github.com/Method-Security/networkscan/generated/go/discover"
	discover "github.com/Method-Security/networkscan/internal/discover"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/spf13/cobra"
)

func (a *NetworkScan) InitDiscoverCommand() {
	discoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover hosts, ports, services, and TLS info",
		Long:  `Discover hosts, ports, services, and TLS info`,
	}

	discoverHostCmd := &cobra.Command{
		Use:   "host",
		Short: "Discover hosts on a network",
		Long:  `Discover hosts on a network`,
		Run: func(cmd *cobra.Command, args []string) {
			if !privileges.IsPrivileged {
				a.OutputSignal.AddError(errors.New("discover host can only be run as a privileged user"))
				return
			}
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			scanType, err := cmd.Flags().GetString("scan-type")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			report, err := discover.RunHostDiscovery(cmd.Context(), target, scanType)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverHostCmd.Flags().String("target", "", "Target IP, host, or CIDR to scan for hosts")
	discoverHostCmd.Flags().String("scan-type", "", "Scan type for host discovery (tcpsyn | tcpack | icmpecho | icmptimestamp | arp | icmpaddressmask)")
	_ = discoverHostCmd.MarkFlagRequired("target")
	discoverCmd.AddCommand(discoverHostCmd)

	discoverOSCmd := &cobra.Command{
		Use:   "os",
		Short: "Fingerprint the operating system on a target host",
		Long:  `Fingerprint the operating system on a target host`,
		Run: func(cmd *cobra.Command, args []string) {
			if !privileges.IsPrivileged {
				a.OutputSignal.AddError(errors.New("discover os can only be run as a privileged user"))
				return
			}
			_, err := exec.LookPath("nmap")
			if err != nil {
				a.OutputSignal.AddError(errors.New("nmap is not installed or is not in the system path"))
				return
			}
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			report, err := discover.RunOsFingerprint(cmd.Context(), target)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverOSCmd.Flags().String("target", "", "Target IP or FQDN to detect")
	_ = discoverOSCmd.MarkFlagRequired("target")
	discoverCmd.AddCommand(discoverOSCmd)

	discoverPortCmd := &cobra.Command{
		Use:   "port",
		Short: "Scan open ports on a target host",
		Long:  `Scan open ports on a target host`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
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
			if scanType != "syn" && scanType != "connect" {
				a.OutputSignal.AddError(errors.New("scan-type must be either syn or connect"))
				return
			}
			report, err := discover.RunPortScan(cmd.Context(), target, ports, topPorts, threads, scanType)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverPortCmd.Flags().String("target", "", "Target IP or FQDN to scan for ports")
	discoverPortCmd.Flags().String("ports", "", "Port/Port Range to scan")
	discoverPortCmd.Flags().String("top-ports", "", "Top Ports to scan (full | 100 | 1000)")
	discoverPortCmd.Flags().Int("threads", 25, "Number of threads to use for scanning")
	discoverPortCmd.Flags().String("scan-type", "syn", "Type of scan to perform (syn | connect)")
	_ = discoverPortCmd.MarkFlagRequired("target")
	discoverCmd.AddCommand(discoverPortCmd)

	discoverServiceCmd := &cobra.Command{
		Use:   "service",
		Short: "Fingerprint a network service behind an open port",
		Long:  `Fingerprint a network service behind an open port`,
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
			report, err := discover.RunServiceFingerprint(cmd.Context(), timeout, target, port)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverServiceCmd.Flags().String("target", "", "Target address (e.g., 192.168.1.1 or example.com)")
	discoverServiceCmd.Flags().Int("port", 0, "Address Port (e.g., 443)")
	discoverServiceCmd.Flags().Int("timeout", 5, "Timeout limit for each handshake in seconds")
	_ = discoverServiceCmd.MarkFlagRequired("target")
	_ = discoverServiceCmd.MarkFlagRequired("port")
	discoverCmd.AddCommand(discoverServiceCmd)

	discoverTlsCmd := &cobra.Command{
		Use:   "tls",
		Short: "Discover TLS Config and Certificate of a network address socket",
		Long:  `Discover TLS Config and Certificate of a network address socket`,
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
			insecure, err := cmd.Flags().GetBool("insecure")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			report, err := discover.GetTLSInfo(cmd.Context(), targets, discoverFern.DiscoverTlsConfig{Timeout: timeout, InsecureSkipVerify: insecure})
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	discoverTlsCmd.Flags().StringSlice("targets", []string{}, "Address of target")
	discoverTlsCmd.Flags().Int("timeout", 30, "Timeout limit for each handshake in seconds")
	discoverTlsCmd.Flags().Bool("insecure", false, "Skip TLS verification")
	discoverCmd.AddCommand(discoverTlsCmd)

	a.RootCmd.AddCommand(discoverCmd)
}

func LoadTLSConfig(targets []string, timeout int, insecure bool) discoverFern.DiscoverTlsConfig {
	config := discoverFern.DiscoverTlsConfig{
		Timeout:            timeout,
		InsecureSkipVerify: insecure,
	}
	return config
}
