// Package main is the entry point for the networkscan application.
package main

import (
	"flag"
	"os"

	"github.com/Method-Security/networkscan/cmd"
)

// version is set during build time via ldflags
var version = "none"

// main initializes and executes the networkscan CLI application.
// It sets up the root command and all subcommands (discover, enumerate, pentest)
// before executing the root command.
func main() {
	flag.Parse()

	networkscan := cmd.NewNetworkScan(version)
	networkscan.InitRootCommand()
	networkscan.InitDiscoverCommand()
	networkscan.InitEnumerateCommand()
	networkscan.InitPentestCommand()

	if err := networkscan.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
