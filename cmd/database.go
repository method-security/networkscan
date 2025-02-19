package cmd

import (
	mysql "github.com/Method-Security/networkscan/internal/database/mysql"
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

			connectionTimeout, err := cmd.Flags().GetInt("connectiontimeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := mysql.RunMySQLEnumerate(cmd.Context(), targets, connectionTimeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	mysqlEnumerateCmd.Flags().StringSlice("targets", []string{}, "Target IP Socket or FQDN Socket to enumerate")
	mysqlEnumerateCmd.Flags().Int("connectiontimeout", 30, "Timeout for Database connection in seconds")
	_ = mysqlEnumerateCmd.MarkFlagRequired("targets")

	mysqlCmd.AddCommand(mysqlEnumerateCmd)

	databaseCmd.AddCommand(mysqlCmd)
	a.RootCmd.AddCommand(databaseCmd)
}
