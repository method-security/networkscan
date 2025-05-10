package cmd

import (
	"errors"

	serviceFern "github.com/Method-Security/networkscan/generated/go/service"
	bruteforcefern "github.com/Method-Security/networkscan/generated/go/service/bruteforce"
	enumerateFern "github.com/Method-Security/networkscan/generated/go/service/enumerate"
	service "github.com/Method-Security/networkscan/internal/service"
	bruteforce "github.com/Method-Security/networkscan/internal/service/bruteforce"
	enumerate "github.com/Method-Security/networkscan/internal/service/enumerate"
	utils "github.com/Method-Security/networkscan/utils"
	"github.com/spf13/cobra"
)

// InitServiceCommand initializes the service command for the networkscan CLI. It also sets up the flags for
// the service command and its subcommands.
func (a *NetworkScan) InitServiceCommand() {
	serviceCmd := &cobra.Command{
		Use:   "service",
		Short: "Discover and interact with network services",
		Long:  `Discover and interact with network services`,
	}

	serviceFingerprintCmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Fingerprint a network service",
		Long:  `Fingerprint a network service`,
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

			report, err := service.RunServiceFingerprint(cmd.Context(), timeout, target, port)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	serviceFingerprintCmd.Flags().String("target", "", "Target address (e.g., 192.168.1.1 or example.com)")
	serviceFingerprintCmd.Flags().Uint16("port", 0, "Address Port (e.g., 443)")
	serviceFingerprintCmd.Flags().Int("timeout", 5, "Timeout limit for each handshake in seconds")

	_ = serviceFingerprintCmd.MarkFlagRequired("target")
	_ = serviceFingerprintCmd.MarkFlagRequired("port")

	serviceCmd.AddCommand(serviceFingerprintCmd)

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
			report, err := bruteforce.Attack(cmd.Context(), bruteForceConfig)
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

	serviceCmd.AddCommand(bruteForceCmd)

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
			report, err := service.GetTLSInfo(cmd.Context(), targets, config)
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

	serviceCmd.AddCommand(tlsCmd)

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate data about a network service",
		Long:  `Enumerate data about a network service`,
	}

	// FTP enumerate
	ftpEnumerateCmd := &cobra.Command{
		Use:   "ftp",
		Short: "Enumerate data about FTP on a target host",
		Long:  `Enumerate data about FTP on a target host`,
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

			report, err := enumerate.RunNetworkApplicationEnumerate(cmd.Context(), targets, enumerateFern.NetworkApplicationFtp, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	ftpEnumerateCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	ftpEnumerateCmd.Flags().Int("timeout", 30, "Total time allowed for enumeration of each target in seconds")
	_ = ftpEnumerateCmd.MarkFlagRequired("targets")

	// SMTP enumerate
	smtpEnumerateCmd := &cobra.Command{
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

			report, err := enumerate.RunNetworkApplicationEnumerate(cmd.Context(), targets, enumerateFern.NetworkApplicationSmtp, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	smtpEnumerateCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	smtpEnumerateCmd.Flags().Int("timeout", 30, "Total time allowed for enumeration of each target in seconds")
	_ = smtpEnumerateCmd.MarkFlagRequired("targets")

	// SSH enumerate
	sshEnumerateCmd := &cobra.Command{
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

			report, err := enumerate.RunNetworkApplicationEnumerate(cmd.Context(), targets, enumerateFern.NetworkApplicationSsh, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	sshEnumerateCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	sshEnumerateCmd.Flags().Int("timeout", 30, "Total time allowed for enumeration of each target in seconds")
	_ = sshEnumerateCmd.MarkFlagRequired("targets")

	enumerateCmd.AddCommand(ftpEnumerateCmd)
	enumerateCmd.AddCommand(smtpEnumerateCmd)
	enumerateCmd.AddCommand(sshEnumerateCmd)
	serviceCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(serviceCmd)
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

func LoadTLSConfig(targets []string, timeout int, insecure bool) serviceFern.ServiceTlsConfig {
	config := serviceFern.ServiceTlsConfig{
		Timeout:            timeout,
		InsecureSkipVerify: insecure,
	}
	return config
}
