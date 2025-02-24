package cmd

import (
	utilsFern "github.com/Method-Security/networkscan/generated/go/utils"
	"github.com/Method-Security/networkscan/utils"
	"github.com/spf13/cobra"
)

func (a *NetworkScan) InitDatabaseCommand() {
	databaseCmd := &cobra.Command{
		Use:   "database",
		Short: "Interact with a Database on a target host",
		Long:  "Interact with a Database on a target host",
	}

	mysqlCmd := &cobra.Command{
		Use:   "mysql",
		Short: "Interact with MySQL on a target host",
		Long:  "Interact with MySQL on a target host",
	}

	mysqlEnumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate data about MySQL on a target host",
		Long:  `Enumerate data about MySQL on a target host`,
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

			report, err := utils.RunNetworkApplicationEnumerate(cmd.Context(), targets, utilsFern.NetworkApplicationMysql, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	mysqlEnumerateCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	mysqlEnumerateCmd.Flags().Int("timeout", 30, "Total time allowed for enumeration of each target in seconds")
	_ = mysqlEnumerateCmd.MarkFlagRequired("targets")

	mysqlCmd.AddCommand(mysqlEnumerateCmd)

	databaseCmd.AddCommand(mysqlCmd)
	a.RootCmd.AddCommand(databaseCmd)
}
