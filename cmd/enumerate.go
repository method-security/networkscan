package cmd

import (
	"fmt"
	"strings"

	// Generated
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	vncfern "github.com/Method-Security/networkscan/generated/go/enumerate/vnc"

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

			vncSkipScreenshot, err := cmd.Flags().GetBool("vnc-skip-screenshot")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			vncPortRange, err := cmd.Flags().GetString("vnc-port-range")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			config := newEnumerateServiceConfig(EnumerateServiceCobraFlags{
				Targets:           targets,
				Service:           serviceEnum,
				Timeout:           timeout,
				Wordlist:          wordlist,
				VncSkipScreenshot: vncSkipScreenshot,
				VncPortRange:      vncPortRange,
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
	enumerateServiceCmd.Flags().String("service", "", "Service to enumerate (ftp, grpc, ike, imap, ipmi, ldap, mongodb, mssql, mysql, pop3, postgres, rdp, redis, smb, smtp, snmp, socks, ssh, vnc)")
	enumerateServiceCmd.Flags().Int("timeout", 30, "Timeout in seconds for enumerating each target")
	enumerateServiceCmd.Flags().StringSlice("wordlist", []string{}, "Custom username wordlist for user enumeration (SMTP VRFY/EXPN/RCPT TO)")
	// VNC-specific flags
	enumerateServiceCmd.Flags().Bool("vnc-skip-screenshot", false, "Skip framebuffer screenshot capture even when None auth is offered (VNC only)")
	enumerateServiceCmd.Flags().String("vnc-port-range", "5900-5910", "Port range to sweep when no explicit port is given (VNC only, e.g. '5900-5910')")

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
	Targets           []string
	Service           enumeratefern.SupportedServiceType
	Timeout           int
	Wordlist          []string
	VncSkipScreenshot bool
	VncPortRange      string
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
	// VNC-specific config
	if flags.Service == enumeratefern.SupportedServiceTypeVnc {
		vncCfg := &vncfern.VncEnumerateConfig{}
		vncCfg.SkipScreenshot = &flags.VncSkipScreenshot
		if flags.VncPortRange != "" {
			vncCfg.PortRange = &flags.VncPortRange
		}
		config.VncConfig = vncCfg
	}
	return config
}
