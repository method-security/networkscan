package cmd

import (
	"errors"
	"fmt"
	"strings"

	// Generated
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	// Internal
	enumerate "github.com/Method-Security/networkscan/internal/enumerate"
	// External
	cobra "github.com/spf13/cobra"
)

// InitEnumerateCommand initializes the enumerate command and its subcommands (ftp, grpc, smtp, ssh).
// Each subcommand implements service-specific enumeration functionality for different network protocols.
func (a *NetworkScan) InitEnumerateCommand() {
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate detailed information about supported network services on target hosts.",
		Long:  `Enumerate detailed information about supported network services on target hosts.`,
	}

	// Service Command
	enumerateServiceCmd := &cobra.Command{
		Use:   "service",
		Short: "Enumerate detailed information about supported network services on target hosts.",
		Long:  `Enumerate detailed information about supported network services on target hosts.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Target flags
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			service, err := cmd.Flags().GetString("service")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			serviceEnum, err := enumeratefern.NewSupportedServiceTypeFromString(strings.ToUpper(service))
			if err != nil {
				a.OutputSignal.AddError(errors.New("invalid service"))
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			attemptDelay, err := cmd.Flags().GetInt("attempt-delay")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if attemptDelay < 0 {
				a.OutputSignal.AddError(fmt.Errorf("attempt-delay must be non-negative"))
				return
			}

			// Extract SMB-specific flags
			noGuest, err := cmd.Flags().GetBool("no-guest")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			noAnonymous, err := cmd.Flags().GetBool("no-anonymous")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			config := enumeratefern.EnumerateServiceConfig{
				Targets: targets,
				Service: serviceEnum,
				Timeout: timeout,
			}
			if attemptDelay > 0 {
				config.AttemptDelay = &attemptDelay
			}
			if noGuest {
				config.NoGuest = &noGuest
			}
			if noAnonymous {
				config.NoAnonymous = &noAnonymous
			}

			// Generate the report
			report, err := enumerate.RunServiceEnumerate(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	enumerateServiceCmd.Flags().StringSlice("targets", []string{}, "List of target addresses (IP:port or hostname:port) to enumerate")
	enumerateServiceCmd.Flags().String("service", "", "Service to enumerate (ftp, grpc, ldap, smb, smtp, ssh)")
	enumerateServiceCmd.Flags().Int("timeout", 30, "Timeout in seconds for enumerating each target")
	enumerateServiceCmd.Flags().Int("attempt-delay", 0, "Delay in seconds between enumeration attempts (0 = no delay)")
	
	// SMB-specific flags
	enumerateServiceCmd.Flags().Bool("no-guest", false, "Disable guest authentication attempts (SMB only)")
	enumerateServiceCmd.Flags().Bool("no-anonymous", false, "Disable anonymous authentication attempts (SMB only)")

	// Mark Required Flags
	_ = enumerateServiceCmd.MarkFlagRequired("targets")
	_ = enumerateServiceCmd.MarkFlagRequired("service")

	// Add Command to 'Enumerate' Command
	enumerateCmd.AddCommand(enumerateServiceCmd)

	// Add Command to 'Root' Command
	a.RootCmd.AddCommand(enumerateCmd)
}
