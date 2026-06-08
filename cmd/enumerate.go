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

			// IMAP-specific flags
			imapUsername, err := cmd.Flags().GetString("imap-username")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			imapPassword, err := cmd.Flags().GetString("imap-password")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			imapMechanism, err := cmd.Flags().GetString("imap-mechanism")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			imapMaxMessages, err := cmd.Flags().GetInt("imap-max-messages")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			imapSearch, err := cmd.Flags().GetString("imap-search")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			imapTargetFolder, err := cmd.Flags().GetString("imap-target-folder")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			imapAllowPlaintext, err := cmd.Flags().GetBool("imap-allow-plaintext-credentials")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			config := newEnumerateServiceConfig(
				targets, serviceEnum, timeout, wordlist,
				imapUsername, imapPassword, imapMechanism, imapMaxMessages, imapSearch,
				imapTargetFolder, imapAllowPlaintext)

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
	enumerateServiceCmd.Flags().String("service", "", "Service to enumerate (ftp, grpc, imap, ldap, mongodb, pop3, smb, smtp, snmp, ssh)")
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

// newEnumerateServiceConfig creates a new EnumerateServiceConfig with the provided parameters.
func newEnumerateServiceConfig(
	targets []string,
	serviceEnum enumeratefern.SupportedServiceType,
	timeout int,
	wordlist []string,
	imapUsername string,
	imapPassword string,
	imapMechanism string,
	imapMaxMessages int,
	imapSearch string,
	imapTargetFolder string,
	imapAllowPlaintext bool,
) enumeratefern.EnumerateServiceConfig {
	config := enumeratefern.EnumerateServiceConfig{
		Targets: targets,
		Service: serviceEnum,
		Timeout: timeout,
	}
	if len(wordlist) > 0 {
		config.Wordlist = wordlist
	}
	if imapUsername != "" {
		config.ImapUsername = &imapUsername
	}
	if imapPassword != "" {
		config.ImapPassword = &imapPassword
	}
	if imapMechanism != "" {
		config.ImapMechanism = &imapMechanism
	}
	if imapMaxMessages > 0 {
		config.ImapMaxMessages = &imapMaxMessages
	}
	if imapSearch != "" {
		config.ImapSearch = &imapSearch
	}
	// Always pass target folder (default is "INBOX" from flag default)
	if imapTargetFolder != "" {
		config.ImapTargetFolder = &imapTargetFolder
	}
	if imapAllowPlaintext {
		config.ImapAllowPlaintextCredentials = &imapAllowPlaintext
	}
	return config
}
