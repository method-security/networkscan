package cmd

import (
	utilsFern "github.com/Method-Security/networkscan/generated/go/utils"
	utils "github.com/Method-Security/networkscan/utils"
	"github.com/spf13/cobra"
)

func (a *NetworkScan) InitSMTPCommand() {
	smtpCmd := &cobra.Command{
		Use:   "smtp",
		Short: "SMTP into a target host",
		Long:  "SMTP into a target host",
	}

	smtpEnumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate data about SMTP on a target host",
		Long:  `Enumerate data about SMTP on a target host`,
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

			report, err := utils.RunNetworkApplicationEnumerate(cmd.Context(), targets, utilsFern.NetworkApplicationSmtp, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	smtpEnumerateCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	smtpEnumerateCmd.Flags().Int("timeout", 30, "Total time allowed for enumeration of each target in seconds")
	_ = smtpEnumerateCmd.MarkFlagRequired("targets")

	smtpCmd.AddCommand(smtpEnumerateCmd)
	a.RootCmd.AddCommand(smtpCmd)
}
