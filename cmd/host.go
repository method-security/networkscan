package cmd

import (
	"errors"
	"os/exec"

	"github.com/Method-Security/networkscan/internal/host"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/spf13/cobra"
)

// InitHostCommand initializes the host command for the networkscan CLI. It also sets up the flags for
// the host command and its subcommands.
func (a *NetworkScan) InitHostCommand() {
	hostCmd := &cobra.Command{
		Use:   "host",
		Short: "Discover and interact with hosts on a network",
		Long:  `Discover and interact with hosts on a network`,
	}

	hostDiscoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover hosts on a network",
		Long:  `Discover hosts on a network`,
		Run: func(cmd *cobra.Command, args []string) {
			// hostdiscover can only be run as a sudoer or privileged user
			if !privileges.IsPrivileged {
				a.OutputSignal.AddError(errors.New("host discover can only be run as a privileged user"))
				return
			}
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			scantype, err := cmd.Flags().GetString("scantype")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := host.RunHostDiscover(cmd.Context(), target, scantype)
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
	hostCmd.AddCommand(hostDiscoverCmd)

	fingerprintCmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Fingerprint the operating system on a target host",
		Long:  `Fingerprint the operating system on a target host`,
		Run: func(cmd *cobra.Command, args []string) {
			// host fingerprint can only be run as a sudoer or privileged user
			if !privileges.IsPrivileged {
				a.OutputSignal.AddError(errors.New("host fingerprint can only be run as a privileged user"))
				return
			}

			// Check if nmap is installed and in the system path
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
			if target == "" {
				a.OutputSignal.AddError(errors.New("target is required"))
				return
			}
			report, err := host.RunHostFingerprint(cmd.Context(), target)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	fingerprintCmd.Flags().String("target", "", "Target IP or FQDN to detect")
	_ = fingerprintCmd.MarkFlagRequired("target")
	hostCmd.AddCommand(fingerprintCmd)

	a.RootCmd.AddCommand(hostCmd)
}
