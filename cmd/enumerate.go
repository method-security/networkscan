package cmd

import (
	"fmt"
	"strings"

	// Generated
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	// Internal
	enumerate "github.com/Method-Security/networkscan/internal/enumerate"
	// External
	cobra "github.com/spf13/cobra"
)

// InitEnumerateCommand initializes the enumerate command and its subcommands (ftp, grpc, smtp, ssh, imap, pop3).
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
				a.OutputSignal.AddError(fmt.Errorf("invalid service '%s': %v", service, err))
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			wordlist, err := cmd.Flags().GetStringSlice("wordlist")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			config := newEnumerateServiceConfig(EnumerateServiceCobraFlags{
				Targets:  targets,
				Service:  serviceEnum,
				Timeout:  timeout,
				Wordlist: wordlist,
			})

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
	enumerateServiceCmd.Flags().String("service", "", "Service to enumerate (ftp, grpc, imap, ldap, mongodb, mysql, pop3, redis, smb, smtp, snmp, socks, ssh)")
	enumerateServiceCmd.Flags().Int("timeout", 30, "Timeout in seconds for enumerating each target")
	enumerateServiceCmd.Flags().StringSlice("wordlist", []string{}, "Custom username wordlist for user enumeration (SMTP VRFY/EXPN/RCPT TO)")

	// Mark Required Flags
	_ = enumerateServiceCmd.MarkFlagRequired("targets")
	_ = enumerateServiceCmd.MarkFlagRequired("service")

	// Add Command to 'Enumerate' Command
	enumerateCmd.AddCommand(enumerateServiceCmd)

	// Add Command to 'Root' Command
	a.RootCmd.AddCommand(enumerateCmd)
}

// EnumerateServiceCobraFlags bundles the flag values consumed by
// newEnumerateServiceConfig. Per-service auth/Mode-B knobs (e.g. for IMAP)
// belong on their own pentest tools (e.g. `pentest service imap`); the
// enumerate stage is pre-auth fingerprinting only.
type EnumerateServiceCobraFlags struct {
	Targets  []string
	Service  enumeratefern.SupportedServiceType
	Timeout  int
	Wordlist []string
}

// newEnumerateServiceConfig creates a new EnumerateServiceConfig from the flag struct.
func newEnumerateServiceConfig(flags EnumerateServiceCobraFlags) enumeratefern.EnumerateServiceConfig {
	config := enumeratefern.EnumerateServiceConfig{
		Targets: flags.Targets,
		Service: flags.Service,
		Timeout: flags.Timeout,
	}
	if len(flags.Wordlist) > 0 {
		config.Wordlist = flags.Wordlist
	}
	return config
}
