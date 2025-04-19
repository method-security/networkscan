package cmd

import (
	utilsFern "github.com/Method-Security/networkscan/generated/go/utils"
	utils "github.com/Method-Security/networkscan/utils"
	"github.com/spf13/cobra"
)

func (a *NetworkScan) InitFTPCommand() {
	ftpCmd := &cobra.Command{
		Use:   "ftp",
		Short: "FTP into a target host",
		Long:  "FTP into a target host",
	}

	ftpEnumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate data about FTP on a target host",
		Long:  `Enumerate data about FTP on a target host`,
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

			report, err := utils.RunNetworkApplicationEnumerate(cmd.Context(), targets, utilsFern.NetworkApplicationFtp, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	ftpEnumerateCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	ftpEnumerateCmd.Flags().Int("timeout", 30, "Total time allowed for enumeration of each target in seconds")
	_ = ftpEnumerateCmd.MarkFlagRequired("targets")

	ftpCmd.AddCommand(ftpEnumerateCmd)
	a.RootCmd.AddCommand(ftpCmd)
}
