package cmd

import (
	"errors"
	"strings"

	// Generated
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	domainfern "github.com/Method-Security/networkscan/generated/go/enumerate/domain"

	// Internal
	enumerate "github.com/Method-Security/networkscan/internal/enumerate"
	domainEnum "github.com/Method-Security/networkscan/internal/enumerate/domain"

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

			config := enumeratefern.EnumerateServiceConfig{
				Targets: targets,
				Service: serviceEnum,
				Timeout: timeout,
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
	enumerateServiceCmd.Flags().String("service", "", "Service to enumerate (ftp, grpc, smb, smtp, ssh)")
	enumerateServiceCmd.Flags().Int("timeout", 30, "Timeout in seconds for enumerating each target")

	// Mark Required Flags
	_ = enumerateServiceCmd.MarkFlagRequired("targets")
	_ = enumerateServiceCmd.MarkFlagRequired("service")

	// Domain Command
	enumerateDomainCmd := &cobra.Command{
		Use:   "domain",
		Short: "Enumerate Active Directory domain objects including users, groups, computers, and more.",
		Long:  `Enumerate Active Directory domain objects including users, groups, computers, domain controllers, organizational units, and group policy objects using LDAP queries.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Target flags
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			username, err := cmd.Flags().GetString("username")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			password, err := cmd.Flags().GetString("password")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			ldapPort, err := cmd.Flags().GetInt("ldap-port")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			useSSL, err := cmd.Flags().GetBool("use-ssl")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			collectionMethodStrings, err := cmd.Flags().GetStringSlice("collection-methods")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			customFilter, err := cmd.Flags().GetString("custom-filter")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			maxResults, err := cmd.Flags().GetInt("max-results")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Convert collection method strings to enum values or use default
			var collectionMethods []domainfern.CollectionMethod
			if len(collectionMethodStrings) == 0 {
				// Use default collection methods: group, localadmin, session, trusts
				collectionMethods = []domainfern.CollectionMethod{
					domainfern.CollectionMethodGroup,
					domainfern.CollectionMethodLocaladmin,
					domainfern.CollectionMethodSession,
					domainfern.CollectionMethodTrusts,
				}
			} else {
				for _, cmStr := range collectionMethodStrings {
					cm, err := domainfern.NewCollectionMethodFromString(strings.ToLower(cmStr))
					if err != nil {
						a.OutputSignal.AddError(errors.New("invalid collection method: " + cmStr))
						return
					}
					collectionMethods = append(collectionMethods, cm)
				}
			}

			config := domainfern.EnumerateDomainConfig{
				Target:            target,
				Domain:            domain,
				Timeout:           timeout,
				CollectionMethods: collectionMethods,
			}

			// Set optional fields
			if username != "" {
				config.Username = &username
			}
			if password != "" {
				config.Password = &password
			}
			if ldapPort != 389 {
				config.LdapPort = &ldapPort
			}
			if useSSL {
				config.UseSsl = &useSSL
			}
			if customFilter != "" {
				config.CustomLdapFilter = &customFilter
			}
			if maxResults > 0 {
				config.MaxResults = &maxResults
			}

			// Generate the report
			library := domainEnum.LibraryEnumerateDomain{}
			result, errs := library.EnumerateDomain(cmd.Context(), config)

			report := domainfern.EnumerateDomainReport{
				Config: &config,
				Result: result,
				Errors: errs,
			}

			a.OutputSignal.Content = report
		},
	}

	enumerateDomainCmd.Flags().String("target", "", "Target domain controller (IP address or hostname)")
	enumerateDomainCmd.Flags().String("domain", "", "Domain name (optional, will be auto-detected if not provided)")
	enumerateDomainCmd.Flags().String("username", "", "Username for authentication (optional, anonymous bind if not provided)")
	enumerateDomainCmd.Flags().String("password", "", "Password for authentication (optional)")
	enumerateDomainCmd.Flags().Int("ldap-port", 389, "LDAP port (default: 389, use 636 for LDAPS)")
	enumerateDomainCmd.Flags().Bool("use-ssl", false, "Use SSL/TLS for LDAP connection")
	enumerateDomainCmd.Flags().Int("timeout", 30, "Timeout in seconds for LDAP operations")
	enumerateDomainCmd.Flags().StringSlice("collection-methods", []string{}, "Collection methods to use (group, localadmin, session, trusts, objectprops, acl, container, dcom, rdp, psremote, loggedon, experimental, all, dconly). Default: group,localadmin,session,trusts")
	enumerateDomainCmd.Flags().String("custom-filter", "", "Custom LDAP filter for advanced queries (use with query-type 'custom')")
	enumerateDomainCmd.Flags().Int("max-results", 0, "Maximum number of results per query type (0 for unlimited)")

	// Mark Required Flags
	_ = enumerateDomainCmd.MarkFlagRequired("target")
	_ = enumerateDomainCmd.MarkFlagRequired("domain")

	// Add Command to 'Enumerate' Command
	enumerateCmd.AddCommand(enumerateServiceCmd)
	enumerateCmd.AddCommand(enumerateDomainCmd)

	// Add Command to 'Root' Command
	a.RootCmd.AddCommand(enumerateCmd)
}
