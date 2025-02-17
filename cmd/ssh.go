package cmd

import (
	ssh "github.com/Method-Security/networkscan/internal/ssh"
	"github.com/spf13/cobra"
)

func (a *NetworkScan) InitSSHCommand() {
	sshCmd := &cobra.Command{
		Use:   "ssh",
		Short: "SSH into a target host",
		Long:  "SSH into a target host",
	}

	sshEnumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate data about SSH on a target host",
		Long:  `Enumerate data about SSH on a target host`,
		Run: func(cmd *cobra.Command, args []string) {

			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			connectionTimeout, err := cmd.Flags().GetInt("connectiontimeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := ssh.RunSSHEnumerate(cmd.Context(), targets, connectionTimeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	sshEnumerateCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	sshEnumerateCmd.Flags().Int("connectiontimeout", 30, "Timeout for each SSH connection in seconds")
	_ = sshEnumerateCmd.MarkFlagRequired("targets")

	sshCmd.AddCommand(sshEnumerateCmd)
	a.RootCmd.AddCommand(sshCmd)
}
