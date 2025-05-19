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

	// GRPC enumerate
	enumerateGrpcCmd := &cobra.Command{
		Use:   "grpc",
		Short: "Enumerate data about GRPC on a target host",
		Long:  `Enumerate data about GRPC on a target host`,
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

			report, err := enumerate.RunNetworkApplicationEnumerate(cmd.Context(), targets, enumerateFern.NetworkApplicationTypeGrpc, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	enumerateGrpcCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	enumerateGrpcCmd.Flags().Int("timeout", 30, "Total time allowed for enumeration of each target in seconds")
	_ = enumerateGrpcCmd.MarkFlagRequired("targets")
	enumerateCmd.AddCommand(enumerateGrpcCmd)

	// SMTP enumerate
	enumerateSMTPCmd := &cobra.Command{
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
	enumerateSMTPCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	enumerateSMTPCmd.Flags().Int("timeout", 30, "Total time allowed for enumeration of each target in seconds")
	_ = enumerateSMTPCmd.MarkFlagRequired("targets")
	enumerateCmd.AddCommand(enumerateSMTPCmd)

	// SSH enumerate
	enumerateSSHCmd := &cobra.Command{
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
	enumerateSSHCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	enumerateSSHCmd.Flags().Int("timeout", 30, "Total time allowed for enumeration of each target in seconds")
	_ = enumerateSSHCmd.MarkFlagRequired("targets")
	enumerateCmd.AddCommand(enumerateSSHCmd)

	a.RootCmd.AddCommand(enumerateCmd)
}
