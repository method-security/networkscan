package cmd

import (
	utilsFern "github.com/Method-Security/networkscan/generated/go/utils"
	utils "github.com/Method-Security/networkscan/utils"
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

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := utils.RunNetworkApplicationEnumerate(cmd.Context(), targets, utilsFern.NetworkApplicationSsh, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	sshEnumerateCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	sshEnumerateCmd.Flags().Int("timeout", 30, "Total time allowed for enumeration of each target in seconds")
	_ = sshEnumerateCmd.MarkFlagRequired("targets")

	sshCmd.AddCommand(sshEnumerateCmd)
	a.RootCmd.AddCommand(sshCmd)
}
