package cmd

import (
	"github.com/Method-Security/networkscan/internal/smtp"
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

			connectionTimeout, err := cmd.Flags().GetInt("connectiontimeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			targetDomain, err := cmd.Flags().GetString("targetdomain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := smtp.RunSMTPEnumerate(cmd.Context(), targets, connectionTimeout, targetDomain)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	smtpEnumerateCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	smtpEnumerateCmd.Flags().Int("connectiontimeout", 30, "Timeout for SMTP connection in seconds")
	smtpEnumerateCmd.Flags().String("targetdomain", "test@example.com", "Target domain to enumerate")
	_ = smtpEnumerateCmd.MarkFlagRequired("targets")

	smtpCmd.AddCommand(smtpEnumerateCmd)
	a.RootCmd.AddCommand(smtpCmd)
}
