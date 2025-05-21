package cmd

import (
	enumerateFern "github.com/Method-Security/networkscan/generated/go/enumerate"
	enumerate "github.com/Method-Security/networkscan/internal/enumerate"
	"github.com/spf13/cobra"
)

func (a *NetworkScan) InitEnumerateCommand() {
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate detailed information about supported network services on target hosts.",
		Long:  `Enumerate detailed information about supported network services on target hosts.`,
	}

	// FTP enumerate
	enumerateFtpCmd := &cobra.Command{
		Use:   "ftp",
		Short: "Gather detailed information about FTP services running on specified targets.",
		Long:  `Gather detailed information about FTP services running on specified targets.`,
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

			report, err := enumerate.RunServiceEnumerate(cmd.Context(), targets, enumerateFern.ServiceTypeFtp, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	enumerateFtpCmd.Flags().StringSlice("targets", []string{}, "List of target addresses (IP:port or hostname:port) to enumerate")
	enumerateFtpCmd.Flags().Int("timeout", 30, "Timeout in seconds for enumerating each target")
	_ = enumerateFtpCmd.MarkFlagRequired("targets")
	enumerateCmd.AddCommand(enumerateFtpCmd)

	// GRPC enumerate
	enumerateGrpcCmd := &cobra.Command{
		Use:   "grpc",
		Short: "Enumerate available gRPC services and methods on specified targets.",
		Long:  `Enumerate available gRPC services and methods on specified targets.`,
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

			report, err := enumerate.RunServiceEnumerate(cmd.Context(), targets, enumerateFern.ServiceTypeGrpc, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	enumerateGrpcCmd.Flags().StringSlice("targets", []string{}, "List of target addresses (IP:port or hostname:port) to enumerate")
	enumerateGrpcCmd.Flags().Int("timeout", 30, "Timeout in seconds for enumerating each target")
	_ = enumerateGrpcCmd.MarkFlagRequired("targets")
	enumerateCmd.AddCommand(enumerateGrpcCmd)

	// SMTP enumerate
	enumerateSMTPCmd := &cobra.Command{
		Use:   "smtp",
		Short: "Gather information about SMTP servers and their supported features on specified targets.",
		Long:  `Gather information about SMTP servers and their supported features on specified targets.`,
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

			report, err := enumerate.RunServiceEnumerate(cmd.Context(), targets, enumerateFern.ServiceTypeSmtp, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	enumerateSMTPCmd.Flags().StringSlice("targets", []string{}, "List of target addresses (IP:port or hostname:port) to enumerate")
	enumerateSMTPCmd.Flags().Int("timeout", 30, "Timeout in seconds for enumerating each target")
	_ = enumerateSMTPCmd.MarkFlagRequired("targets")
	enumerateCmd.AddCommand(enumerateSMTPCmd)

	// SSH enumerate
	enumerateSSHCmd := &cobra.Command{
		Use:   "ssh",
		Short: "Enumerate SSH server details, supported authentication methods, and features on specified targets.",
		Long:  `Enumerate SSH server details, supported authentication methods, and features on specified targets.`,
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

			report, err := enumerate.RunServiceEnumerate(cmd.Context(), targets, enumerateFern.ServiceTypeSsh, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	enumerateSSHCmd.Flags().StringSlice("targets", []string{}, "List of target addresses (IP:port or hostname:port) to enumerate")
	enumerateSSHCmd.Flags().Int("timeout", 30, "Timeout in seconds for enumerating each target")
	_ = enumerateSSHCmd.MarkFlagRequired("targets")
	enumerateCmd.AddCommand(enumerateSSHCmd)

	a.RootCmd.AddCommand(enumerateCmd)
}
