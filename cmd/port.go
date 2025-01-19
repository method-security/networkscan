package cmd

import (
	"errors"

	"github.com/Method-Security/networkscan/internal/port"
	"github.com/spf13/cobra"
)

// InitPortCommand initializes the port command for the networkscan CLI. It also sets up the flags for the port
// command and its subcommands.
func (a *NetworkScan) InitPortCommand() {
	portCmd := &cobra.Command{
		Use:   "port",
		Short: "Scan and interact with ports on a network",
		Long:  "Scan and interact with ports on a network",
	}

	portScanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan for open ports on a target host",
		Long:  `Scan for open ports on a target host`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if target == "" {
				a.OutputSignal.AddError(errors.New("target is required"))
				return
			}
			ports, err := cmd.Flags().GetString("ports")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			topport, err := cmd.Flags().GetString("topports")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			scantype, err := cmd.Flags().GetString("scantype")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if scantype != "syn" && scantype != "connect" {
				a.OutputSignal.AddError(errors.New("scantype must be either syn or connect"))
				return
			}
			report, err := port.RunPortScan(cmd.Context(), target, ports, topport, threads, scantype)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	portScanCmd.Flags().String("target", "", "Target IP or FQDN to scan for ports")
	portScanCmd.Flags().String("ports", "", "Port/Port Range to scan")
	portScanCmd.Flags().String("topports", "", "Top Ports to scan (full | 100 |1000)")
	portScanCmd.Flags().Int("threads", 25, "Number of threads to use for scanning")
	portScanCmd.Flags().String("scantype", "syn", "Type of scan to perform (syn | connect)")
	_ = portScanCmd.MarkFlagRequired("target")

	portScanValidateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Scan for open ports on a target host and validate their status using http requests",
		Long:  `Scan for open ports on a target host and validate their status using http requests`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if target == "" {
				a.OutputSignal.AddError(errors.New("target is required"))
				return
			}
			ports, err := cmd.Flags().GetString("ports")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			topport, err := cmd.Flags().GetString("topports")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			scantype, err := cmd.Flags().GetString("scantype")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if scantype != "syn" && scantype != "connect" {
				a.OutputSignal.AddError(errors.New("scantype must be either syn or connect"))
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			httpsRequest, err := cmd.Flags().GetBool("httpsrequest")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			tlsVerify, err := cmd.Flags().GetBool("tlsverify")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			report, err := port.RunPortScanValidate(cmd.Context(), target, ports, topport, threads, scantype, timeout, httpsRequest, tlsVerify)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	portScanValidateCmd.Flags().String("target", "", "Target IP or FQDN to scan for ports")
	portScanValidateCmd.Flags().String("ports", "", "Port/Port Range to scan")
	portScanValidateCmd.Flags().String("topports", "", "Top Ports to scan (full | 100 |1000)")
	portScanValidateCmd.Flags().Int("threads", 25, "Number of threads to use for scanning")
	portScanValidateCmd.Flags().String("scantype", "syn", "Type of scan to perform (syn | connect)")
	portScanValidateCmd.Flags().Int("timeout", 5, "Timeout limit for each handshake in seconds")
	portScanValidateCmd.Flags().Bool("httpsrequest", true, "Only scan https ports")
	portScanValidateCmd.Flags().Bool("tlsverify", true, "Verify TLS certificates")
	_ = portScanCmd.MarkFlagRequired("target")

	portScanCmd.AddCommand(portScanValidateCmd)

	portCmd.AddCommand(portScanCmd)

	a.RootCmd.AddCommand(portCmd)
}
