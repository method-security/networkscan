package cmd

import (
	enumerateFern "github.com/Method-Security/networkscan/generated/go/enumerate"
	enumerate "github.com/Method-Security/networkscan/internal/enumerate"
	"github.com/spf13/cobra"
)

func (a *NetworkScan) InitEnumerateCommand() {
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate information about network services",
		Long:  `Enumerate information about network services`,
	}

	// FTP enumerate
	enumerateFtpCmd := &cobra.Command{
		Use:   "ftp",
		Short: "Enumerate information about FTP on a target host",
		Long:  `Enumerate information about FTP on a target host`,
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

			report, err := enumerate.RunNetworkApplicationEnumerate(cmd.Context(), targets, enumerateFern.NetworkApplicationTypeFtp, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	enumerateFtpCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	enumerateFtpCmd.Flags().Int("timeout", 30, "Total time allowed for enumeration of each target in seconds")
	_ = enumerateFtpCmd.MarkFlagRequired("targets")
	enumerateCmd.AddCommand(enumerateFtpCmd)

	// SMTP enumerate
	enumerateSmtpCmd := &cobra.Command{
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

			report, err := enumerate.RunNetworkApplicationEnumerate(cmd.Context(), targets, enumerateFern.NetworkApplicationTypeSmtp, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	enumerateSmtpCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	enumerateSmtpCmd.Flags().Int("timeout", 30, "Total time allowed for enumeration of each target in seconds")
	_ = enumerateSmtpCmd.MarkFlagRequired("targets")
	enumerateCmd.AddCommand(enumerateSmtpCmd)

	// SSH enumerate
	enumerateSshCmd := &cobra.Command{
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

			report, err := enumerate.RunNetworkApplicationEnumerate(cmd.Context(), targets, enumerateFern.NetworkApplicationTypeSsh, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	enumerateSshCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	enumerateSshCmd.Flags().Int("timeout", 30, "Total time allowed for enumeration of each target in seconds")
	_ = enumerateSshCmd.MarkFlagRequired("targets")
	enumerateCmd.AddCommand(enumerateSshCmd)

	a.RootCmd.AddCommand(enumerateCmd)
}
