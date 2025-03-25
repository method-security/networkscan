package cmd

import (
	"errors"
	"strings"

	addressfern "github.com/Method-Security/networkscan/generated/go/address"
	bruteforcefern "github.com/Method-Security/networkscan/generated/go/address/bruteforce"
	"github.com/Method-Security/networkscan/internal/address"
	bruteforce "github.com/Method-Security/networkscan/internal/address/bruteforce"
	"github.com/Method-Security/networkscan/internal/address/fingerprint"
	"github.com/Method-Security/networkscan/utils"
	"github.com/spf13/cobra"
)

// InitAddressCommand initializes the address command for the networkscan CLI. It also sets up the flags for
// the address command and its subcommands.
func (a *NetworkScan) InitAddressCommand() {
	addressCmd := &cobra.Command{
		Use:   "address",
		Short: "Discover and interact with network addresses",
		Long:  `Discover and interact with network addresses`,
	}

	bannerGrabCmd := &cobra.Command{
		Use:   "bannergrab",
		Short: "Grab banner from a network address",
		Long:  `Grab banner from a network address`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			port, err := cmd.Flags().GetUint16("port")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := address.RunBannerGrab(cmd.Context(), timeout, target, port)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	bannerGrabCmd.Flags().String("target", "", "Target address (e.g., 192.168.1.1 or example.com)")
	bannerGrabCmd.Flags().Uint16("port", 0, "Address Port (e.g., 443)")
	bannerGrabCmd.Flags().Int("timeout", 5, "Timeout limit for each handshake in seconds")

	_ = bannerGrabCmd.MarkFlagRequired("target")
	_ = bannerGrabCmd.MarkFlagRequired("port")

	addressCmd.AddCommand(bannerGrabCmd)

	bruteForceCmd := &cobra.Command{
		Use:   "bruteforce",
		Short: "Execute a Bruteforce attack against an application",
		Long:  `Execute a Bruteforce attack against an application`,
		Run: func(cmd *cobra.Command, args []string) {

			// Targets
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Module
			module, err := cmd.Flags().GetString("module")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			moduleEnum, err := bruteforcefern.NewModuleTypeFromString(module)
			if err != nil {
				a.OutputSignal.AddError(errors.New("invalid module"))
				return
			}

			// Usernames
			usernames, err := cmd.Flags().GetStringSlice("usernames")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			usernameFiles, err := cmd.Flags().GetStringSlice("usernamelists")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			usernamesFromFiles, err := utils.GetEntriesFromFiles(usernameFiles)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			allUsernames := append(usernames, usernamesFromFiles...)

			// Passwords
			passwords, err := cmd.Flags().GetStringSlice("passwords")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			passwordFiles, err := cmd.Flags().GetStringSlice("passwordlists")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			passwordsFromFiles, err := utils.GetEntriesFromFiles(passwordFiles)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			allPasswords := append(passwords, passwordsFromFiles...)

			// Attack Configurations
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			sleep, err := cmd.Flags().GetInt("sleep")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			retries, err := cmd.Flags().GetInt("retries")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			successfulOnly, err := cmd.Flags().GetBool("successfulonly")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			stopFirstSuccess, err := cmd.Flags().GetBool("stopfirstsuccess")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			bruteForceConfig, err := LoadBruteForceConfig(moduleEnum, targets, allUsernames, allPasswords, timeout, sleep, retries, successfulOnly, stopFirstSuccess)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate Report
			report, err := bruteforce.BruteForceAttack(cmd.Context(), bruteForceConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	bruteForceCmd.Flags().StringSlice("targets", []string{}, "Address of target")
	bruteForceCmd.Flags().String("module", "", "Module type (ie.SSH)")
	bruteForceCmd.Flags().StringSlice("usernames", []string{}, "Username to use in attack")
	bruteForceCmd.Flags().StringSlice("passwords", []string{}, "Password to use in attack")
	bruteForceCmd.Flags().StringSlice("usernamelists", []string{}, "File paths containing usernames to use in attack")
	bruteForceCmd.Flags().StringSlice("passwordlists", []string{}, "File paths containing passwords to use in attack")
	bruteForceCmd.Flags().Int("timeout", 3000, "Timeout per request (MilliSeconds)")
	bruteForceCmd.Flags().Int("sleep", 3000, "Sleep time between requests (MilliSeconds)")
	bruteForceCmd.Flags().Int("retries", 2, "Number of Attempts per credential pair")
	bruteForceCmd.Flags().Bool("successfulonly", false, "Only show successful attempts")
	bruteForceCmd.Flags().Bool("stopfirstsuccess", false, "Stop on the first successful login")

	_ = bruteForceCmd.MarkFlagRequired("targets")
	_ = bruteForceCmd.MarkFlagRequired("module")

	addressCmd.AddCommand(bruteForceCmd)

	tlsCmd := &cobra.Command{
		Use:   "tls",
		Short: "Grab TLS Config and Certificate of a network address socket",
		Long:  `Grab TLS Config and Certificate of a network address socket`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

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
			insecure, err := cmd.Flags().GetBool("insecure")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			config := LoadTLSConfig(targets, timeout, insecure)
			report, err := address.GetTLSInfo(cmd.Context(), targets, config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	tlsCmd.Flags().StringSlice("targets", []string{}, "Address of target")
	tlsCmd.Flags().Int("timeout", 30, "Timeout limit for each handshake in seconds")
	tlsCmd.Flags().Bool("insecure", false, "Skip TLS verification")

	addressCmd.AddCommand(tlsCmd)

	fingerprintCmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Fingerprint a network address",
		Long:  `Fingerprint a network address`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Targets
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config
			resourceType, err := cmd.Flags().GetString("resourcetype")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			resourceTypeEnum, err := validateAddressFingerprintResourceType(resourceType)
			if err != nil {
				a.OutputSignal.AddError(errors.New("input resourcetype is invalid"))
				return
			}

			modules, err := cmd.Flags().GetStringSlice("modules")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			modulesEnum, err := validateAddressFingerprintResourseModuleSelection(*resourceTypeEnum, modules)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			insecure, err := cmd.Flags().GetBool("insecure")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			successfulOnly, err := cmd.Flags().GetBool("successfulonly")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			config := LoadFingerprintConfig(targets, *resourceTypeEnum, modulesEnum, insecure, successfulOnly, timeout)

			engine := fingerprint.NewEngine(&config)

			report, err := engine.RunAddressFingerprint(cmd.Context())
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	fingerprintCmd.Flags().StringSlice("targets", []string{}, "Address of target")
	fingerprintCmd.Flags().String("resourcetype", "", "Resource type to fingerprint")
	fingerprintCmd.Flags().StringSlice("modules", []string{}, "Modules to use for fingerprinting")
	fingerprintCmd.Flags().Int("timeout", 30, "Timeout limit for each handshake in seconds")
	fingerprintCmd.Flags().Bool("successfulonly", false, "Only show successful attempts")
	fingerprintCmd.Flags().Bool("insecure", false, "Skip TLS verification")

	addressCmd.AddCommand(fingerprintCmd)

	a.RootCmd.AddCommand(addressCmd)
}

func LoadBruteForceConfig(module bruteforcefern.ModuleType, targets []string, usernames []string, passwords []string, timeout int, sleep int, retries int, successfulOnly bool, stopFirstSuccess bool) (*bruteforcefern.BruteForceRunConfig, error) {
	config := &bruteforcefern.BruteForceRunConfig{
		Module:           module,
		Targets:          targets,
		Usernames:        usernames,
		Passwords:        passwords,
		Timeout:          timeout,
		Sleep:            sleep,
		Retries:          retries,
		SuccessfulOnly:   successfulOnly,
		StopFirstSuccess: stopFirstSuccess,
	}
	if config.Timeout < 1 {
		return nil, errors.New("timeout must be greater than 0")
	}
	if config.Sleep < 0 {
		return nil, errors.New("sleep time cannot be negative")
	}
	if config.Retries < 0 {
		return nil, errors.New("retries cannot be negative")
	}
	return config, nil
}

func LoadTLSConfig(targets []string, timeout int, insecure bool) addressfern.AddressTlsConfig {
	config := addressfern.AddressTlsConfig{
		Timeout:            timeout,
		InsecureSkipVerify: insecure,
	}
	return config
}

func validateAddressFingerprintResourceType(resourceType string) (*addressfern.AddressFingerprintResourceType, error) {
	resourceTypeEnum, err := addressfern.NewAddressFingerprintResourceTypeFromString(strings.ToUpper(resourceType))
	if err != nil {
		return nil, err
	}
	return &resourceTypeEnum, nil
}

func validateAddressFingerprintResourseModuleSelection(resourceType addressfern.AddressFingerprintResourceType, modules []string) ([]*addressfern.AddressFingerprintResourceModule, error) {
	moduleEnums := []*addressfern.AddressFingerprintResourceModule{}
	if len(modules) == 0 {
		return nil, nil
	}
	if resourceType == addressfern.AddressFingerprintResourceTypeRemoteaccess {
		for _, module := range modules {
			moduleName, err := addressfern.NewRemoteAccessModuleFromString(strings.ToUpper(module))
			if err != nil {
				return nil, err
			}
			moduleEnum := addressfern.NewAddressFingerprintResourceModuleFromRemoteAccessModule(moduleName)
			moduleEnums = append(moduleEnums, moduleEnum)
		}
	}

	return moduleEnums, nil
}

func LoadFingerprintConfig(targets []string, resourceType addressfern.AddressFingerprintResourceType, modules []*addressfern.AddressFingerprintResourceModule, insecure bool, successfulOnly bool, timeout int) addressfern.AddressFingerprintConfig {
	config := addressfern.AddressFingerprintConfig{
		Targets:            targets,
		ResourceType:       resourceType,
		Modules:            modules,
		InsecureSkipVerify: insecure,
		SuccessfulOnly:     successfulOnly,
		Timeout:            timeout,
	}
	return config
}
