// Package cmd implements the CobraCLI commands for the networkscan CLI. Subcommands for the CLI should all live within
// this package. Logic should be delegated to internal packages and functions to keep the CLI commands clean and
// focused on CLI I/O.
package cmd

import (
	"errors"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/internal/config"
	"github.com/Method-Security/pkg/signal"
	"github.com/Method-Security/pkg/writer"
	"github.com/palantir/pkg/datetime"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

// NetworkScan is the main struct for the networkscan CLI that holds the root command and all subcommands used throughout
// execution of the CLI. It is also responsible for  holding the Output configuration and the Output signal that
// is used by subcommands. The Output Signal is used to write the output of the command to the desired output format
// after the execution of the invoked command's Run function.
type NetworkScan struct {
	Version      string
	RootFlags    config.RootFlags
	OutputConfig writer.OutputConfig
	OutputSignal signal.Signal
	RootCmd      *cobra.Command
}

// NewNetworkScan creates a new NetworkScan struct with the provided version string. The NetworkScan struct is used to
// hold the root command and all subcommands used throughout execution of the CLI. We pass the version command here
// from the main.go file, where we set the version string during the build process.
func NewNetworkScan(version string) *NetworkScan {
	startedAt := datetime.DateTime(time.Now())
	networkScan := NetworkScan{
		Version: version,
		RootFlags: config.RootFlags{
			Quiet:   false,
			Verbose: false,
		},
		OutputConfig: writer.NewOutputConfig(nil, writer.NewFormat(writer.SIGNAL)),
		OutputSignal: signal.NewSignal(nil, &startedAt, nil, 0, nil),
	}
	return &networkScan
}

// InitRootCommand initializes the root command for the networkscan CLI. This function sets up the root command and
// version command for the CLI. It also sets up the persistent flags for the root command, such as the log level, output
// format, and output file.
// Critically, this sets the PersistentPreRunE and PersistentPostRunE functions that are inherited by all subcommands.
// The PersistentPreRunE function is used to validate the output flags. The PersistentPostRunE function is used to write
// the output of the command to the desired output format after the execution of the invoked command's Run function.
func (a *NetworkScan) InitRootCommand() {
	var outputFormat string
	var outputFile string
	a.RootCmd = &cobra.Command{
		Use:   "networkscan",
		Short: "Scan Network resources",
		Long:  `Scan Network resources`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			format, err := validateOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			var outputFilePointer *string
			if outputFile != "" {
				outputFilePointer = &outputFile
			} else {
				outputFilePointer = nil
			}
			a.OutputConfig = writer.NewOutputConfig(outputFilePointer, format)
			cmd.SetContext(svc1log.WithLogger(cmd.Context(), config.InitializeLogging(cmd, &a.RootFlags)))
			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			completedAt := datetime.DateTime(time.Now())
			a.OutputSignal.CompletedAt = &completedAt
			return writer.Write(
				a.OutputSignal.Content,
				a.OutputConfig,
				&a.OutputSignal.StartedAt,
				a.OutputSignal.CompletedAt,
				a.OutputSignal.Status,
				a.OutputSignal.ErrorMessage,
			)
		},
	}

	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Quiet, "quiet", "q", false, "Suppress output")
	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Verbose, "verbose", "v", false, "Verbose output")
	a.RootCmd.PersistentFlags().StringVarP(&outputFile, "output-file", "f", "", "Path to output file. If blank, will output to STDOUT")
	a.RootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "signal", "Output format (signal, json, yaml). Default value is signal")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Prints the version number of networkscan",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(a.Version)
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	a.RootCmd.AddCommand(versionCmd)
}

func validateOutputFormat(output string) (writer.Format, error) {
	var format writer.FormatValue
	switch strings.ToLower(output) {
	case "json":
		format = writer.JSON
	case "yaml":
		format = writer.YAML
	case "signal":
		format = writer.SIGNAL
	default:
		return writer.Format{}, errors.New("invalid output format. Valid formats are: json, yaml, signal")
	}
	return writer.NewFormat(format), nil
}
