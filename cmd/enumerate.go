package cmd

import (
	"fmt"
	"strings"

	// Generated
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	imapfern "github.com/Method-Security/networkscan/generated/go/enumerate/imap"

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

			// IMAP-specific flags
			imapConfig, err := readImapEnumerateConfig(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			config := newEnumerateServiceConfig(EnumerateServiceCobraFlags{
				Targets:  targets,
				Service:  serviceEnum,
				Timeout:  timeout,
				Wordlist: wordlist,
				Imap:     imapConfig,
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
	enumerateServiceCmd.Flags().String("service", "", "Service to enumerate (ftp, grpc, imap, ldap, mongodb, pop3, smb, smtp, snmp, socks, ssh)")
	enumerateServiceCmd.Flags().Int("timeout", 30, "Timeout in seconds for enumerating each target")
	enumerateServiceCmd.Flags().StringSlice("wordlist", []string{}, "Custom username wordlist for user enumeration (SMTP VRFY/EXPN/RCPT TO)")

	// IMAP-specific flags
	enumerateServiceCmd.Flags().String("imap-username", "", "IMAP username for authenticated enumeration (Mode B)")
	enumerateServiceCmd.Flags().String("imap-password", "", "IMAP password for authenticated enumeration (Mode B)")
	enumerateServiceCmd.Flags().String("imap-mechanism", "", "SASL mechanism override (PLAIN, LOGIN, CRAM-MD5, GSSAPI, XOAUTH2)")
	enumerateServiceCmd.Flags().Int("imap-max-messages", 0, "Maximum number of message headers to fetch via UID FETCH (0 = none)")
	enumerateServiceCmd.Flags().String("imap-search", "", "IMAP SEARCH expression applied after authentication (e.g. 'UNSEEN', 'FROM admin')")
	enumerateServiceCmd.Flags().String("imap-target-folder", "INBOX", "Folder to EXAMINE for detailed status (default: INBOX)")
	enumerateServiceCmd.Flags().Bool("imap-allow-plaintext-credentials", false, "Allow PLAIN/LOGIN auth over unencrypted transport (not recommended)")

	// Mark Required Flags
	_ = enumerateServiceCmd.MarkFlagRequired("targets")
	_ = enumerateServiceCmd.MarkFlagRequired("service")

	// Add Command to 'Enumerate' Command
	enumerateCmd.AddCommand(enumerateServiceCmd)

	// Add Command to 'Root' Command
	a.RootCmd.AddCommand(enumerateCmd)
}

// EnumerateServiceCobraFlags bundles the flag values consumed by
// newEnumerateServiceConfig, keeping per-service config nested rather than
// inflating the top-level argument list.
type EnumerateServiceCobraFlags struct {
	Targets  []string
	Service  enumeratefern.SupportedServiceType
	Timeout  int
	Wordlist []string
	Imap     *imapfern.ImapEnumerateConfig
}

// readImapEnumerateConfig pulls the IMAP-specific cobra flags off cmd and
// wraps them into an ImapEnumerateConfig, returning nil when no IMAP flag
// was set (i.e. the user is not enumerating IMAP).
func readImapEnumerateConfig(cmd *cobra.Command) (*imapfern.ImapEnumerateConfig, error) {
	imapUsername, err := cmd.Flags().GetString("imap-username")
	if err != nil {
		return nil, err
	}
	imapPassword, err := cmd.Flags().GetString("imap-password")
	if err != nil {
		return nil, err
	}
	imapMechanism, err := cmd.Flags().GetString("imap-mechanism")
	if err != nil {
		return nil, err
	}
	imapMaxMessages, err := cmd.Flags().GetInt("imap-max-messages")
	if err != nil {
		return nil, err
	}
	imapSearch, err := cmd.Flags().GetString("imap-search")
	if err != nil {
		return nil, err
	}
	imapTargetFolder, err := cmd.Flags().GetString("imap-target-folder")
	if err != nil {
		return nil, err
	}
	imapAllowPlaintext, err := cmd.Flags().GetBool("imap-allow-plaintext-credentials")
	if err != nil {
		return nil, err
	}

	imapConfig := &imapfern.ImapEnumerateConfig{}
	set := false
	if imapUsername != "" {
		imapConfig.Username = &imapUsername
		set = true
	}
	if imapPassword != "" {
		imapConfig.Password = &imapPassword
		set = true
	}
	if imapMechanism != "" {
		imapConfig.Mechanism = &imapMechanism
		set = true
	}
	if imapMaxMessages > 0 {
		imapConfig.MaxMessages = &imapMaxMessages
		set = true
	}
	if imapSearch != "" {
		imapConfig.Search = &imapSearch
		set = true
	}
	// Always pass target folder (default is "INBOX" from flag default)
	if imapTargetFolder != "" {
		imapConfig.TargetFolder = &imapTargetFolder
		set = true
	}
	if imapAllowPlaintext {
		imapConfig.AllowPlaintextCredentials = &imapAllowPlaintext
		set = true
	}
	if !set {
		return nil, nil
	}
	return imapConfig, nil
}

// newEnumerateServiceConfig creates a new EnumerateServiceConfig from the
// flag struct, nesting per-service config (e.g. ImapConfig) instead of
// inflating EnumerateServiceConfig with service-specific fields.
func newEnumerateServiceConfig(flags EnumerateServiceCobraFlags) enumeratefern.EnumerateServiceConfig {
	config := enumeratefern.EnumerateServiceConfig{
		Targets: flags.Targets,
		Service: flags.Service,
		Timeout: flags.Timeout,
	}
	if len(flags.Wordlist) > 0 {
		config.Wordlist = flags.Wordlist
	}
	if flags.Imap != nil {
		config.ImapConfig = flags.Imap
	}
	return config
}
