package cmd

import (
	enumerateFern "github.com/Method-Security/networkscan/generated/go/enumerate"
	enumerate "github.com/Method-Security/networkscan/internal/enumerate"
	"github.com/spf13/cobra"
)

func (a *NetworkScan) InitEnumerateCommand() {
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate data about network services",
		Long:  `Enumerate data about network services`,
	}

	// FTP enumerate
	ftpEnumerateCmd := &cobra.Command{
		Use:   "ftp",
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

			report, err := enumerate.RunNetworkApplicationEnumerate(cmd.Context(), targets, enumerateFern.NetworkApplicationFtp, timeout)
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

	// SMTP enumerate
	smtpEnumerateCmd := &cobra.Command{
		Use:   "smtp",
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

			report, err := enumerate.RunNetworkApplicationEnumerate(cmd.Context(), targets, enumerateFern.NetworkApplicationSmtp, timeout)
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

	// SSH enumerate
	sshEnumerateCmd := &cobra.Command{
		Use:   "ssh",
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

			report, err := enumerate.RunNetworkApplicationEnumerate(cmd.Context(), targets, enumerateFern.NetworkApplicationSsh, timeout)
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

	enumerateCmd.AddCommand(ftpEnumerateCmd)
	enumerateCmd.AddCommand(smtpEnumerateCmd)
	enumerateCmd.AddCommand(sshEnumerateCmd)

	a.RootCmd.AddCommand(enumerateCmd)
}
