// Package config contains common configuration values that are used by the various commands and subcommands in the CLI.
package config

// RootFlags defines the global flags that are available to all commands in the CLI.
// These flags control the verbosity and output behavior of the application.
type RootFlags struct {
	Quiet   bool // When true, suppresses all output except errors
	Verbose bool // When true, enables detailed debug logging
}
