package cmd

import (
	"errors"
	"os/exec"

	discoverFern "github.com/Method-Security/networkscan/generated/go/discover"
	discover "github.com/Method-Security/networkscan/internal/discover"
	"github.com/spf13/cobra"
)

func (a *NetworkScan) InitDiscoverCommand() {
	discoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover hosts, ports, services, and TLS info",
		Long:  `Discover hosts, ports, services, and TLS info`,
	}

	hostDiscoverCmd := &cobra.Command{
		Use:   "host",
		Short: "Discover hosts on a network",
		Long:  `Discover hosts on a network`,
		Run: func(cmd *cobra.Command, args []string) {
			if !isPrivileged() {
				a.OutputSignal.AddError(errors.New("host discover can only be run as a privileged user"))
				return
			}
			target, _ := cmd.Flags().GetString("target")
			scantype, _ := cmd.Flags().GetString("scantype")
			report, err := discover.RunHostDiscover(cmd.Context(), target, scantype)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	hostDiscoverCmd.Flags().String("target", "", "Target IP, host, or CIDR to scan for hosts")
	hostDiscoverCmd.Flags().String("scantype", "", "Scan type for host discovery (tcpsyn | tcpack | icmpecho | icmptimestamp | arp | icmpaddressmask)")
	_ = hostDiscoverCmd.MarkFlagRequired("target")
	discoverCmd.AddCommand(hostDiscoverCmd)

	hostFingerprintCmd := &cobra.Command{
		Use:   "os",
		Short: "Fingerprint the operating system on a target host",
		Long:  `Fingerprint the operating system on a target host`,
		Run: func(cmd *cobra.Command, args []string) {
			if !isPrivileged() {
				a.OutputSignal.AddError(errors.New("host fingerprint can only be run as a privileged user"))
				return
			}
			_, err := exec.LookPath("nmap")
			if err != nil {
				a.OutputSignal.AddError(errors.New("nmap is not installed or is not in the system path"))
				return
			}
			target, _ := cmd.Flags().GetString("target")
			report, err := discover.RunHostFingerprint(cmd.Context(), target)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	hostFingerprintCmd.Flags().String("target", "", "Target IP or FQDN to detect")
	_ = hostFingerprintCmd.MarkFlagRequired("target")
	discoverCmd.AddCommand(hostFingerprintCmd)

	portScanCmd := &cobra.Command{
		Use:   "port",
		Short: "Scan for open ports on a target host",
		Long:  `Scan for open ports on a target host`,
		Run: func(cmd *cobra.Command, args []string) {
			target, _ := cmd.Flags().GetString("target")
			ports, _ := cmd.Flags().GetString("ports")
			topport, _ := cmd.Flags().GetString("topports")
			threads, _ := cmd.Flags().GetInt("threads")
			scantype, _ := cmd.Flags().GetString("scantype")
			if scantype != "syn" && scantype != "connect" {
				a.OutputSignal.AddError(errors.New("scantype must be either syn or connect"))
				return
			}
			report, err := discover.RunPortScan(cmd.Context(), target, ports, topport, threads, scantype)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	portScanCmd.Flags().String("target", "", "Target IP or FQDN to scan for ports")
	portScanCmd.Flags().String("ports", "", "Port/Port Range to scan")
	portScanCmd.Flags().String("topports", "", "Top Ports to scan (full | 100 |1000)")
	portScanCmd.Flags().Int("threads", 25, "Number of threads to use for scanning")
	portScanCmd.Flags().String("scantype", "syn", "Type of scan to perform (syn | connect)")
	_ = portScanCmd.MarkFlagRequired("target")
	discoverCmd.AddCommand(portScanCmd)

	serviceFingerprintCmd := &cobra.Command{
		Use:   "service",
		Short: "Fingerprint a network service",
		Long:  `Fingerprint a network service`,
		Run: func(cmd *cobra.Command, args []string) {
			target, _ := cmd.Flags().GetString("target")
			port, _ := cmd.Flags().GetUint16("port")
			timeout, _ := cmd.Flags().GetInt("timeout")
			report, err := discover.RunServiceFingerprint(cmd.Context(), timeout, target, port)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	serviceFingerprintCmd.Flags().String("target", "", "Target address (e.g., 192.168.1.1 or example.com)")
	serviceFingerprintCmd.Flags().Uint16("port", 0, "Address Port (e.g., 443)")
	serviceFingerprintCmd.Flags().Int("timeout", 5, "Timeout limit for each handshake in seconds")
	_ = serviceFingerprintCmd.MarkFlagRequired("target")
	_ = serviceFingerprintCmd.MarkFlagRequired("port")
	discoverCmd.AddCommand(serviceFingerprintCmd)

	tlsCmd := &cobra.Command{
		Use:   "tls",
		Short: "Grab TLS Config and Certificate of a network address socket",
		Long:  `Grab TLS Config and Certificate of a network address socket`,
		Run: func(cmd *cobra.Command, args []string) {
			targets, _ := cmd.Flags().GetStringSlice("targets")
			timeout, _ := cmd.Flags().GetInt("timeout")
			insecure, _ := cmd.Flags().GetBool("insecure")
			report, err := discover.GetTLSInfo(cmd.Context(), targets, discoverFern.ServiceTlsConfig{Timeout: timeout, InsecureSkipVerify: insecure})
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	tlsCmd.Flags().StringSlice("targets", []string{}, "Address of target")
	tlsCmd.Flags().Int("timeout", 30, "Timeout limit for each handshake in seconds")
	tlsCmd.Flags().Bool("insecure", false, "Skip TLS verification")
	discoverCmd.AddCommand(tlsCmd)

	a.RootCmd.AddCommand(discoverCmd)
}

func isPrivileged() bool {
	// Use the same privilege check as before
	return true // TODO: Replace with actual privilege check logic
}

func LoadTLSConfig(targets []string, timeout int, insecure bool) discoverFern.ServiceTlsConfig {
	config := discoverFern.ServiceTlsConfig{
		Timeout:            timeout,
		InsecureSkipVerify: insecure,
	}
	return config
}
