package main

import (
	"flag"
	"os"

	"github.com/Method-Security/networkscan/cmd"
)

var version = "none"

func main() {
	flag.Parse()

	networkscan := cmd.NewNetworkScan(version)
	networkscan.InitRootCommand()
	networkscan.InitHostCommand()
	networkscan.InitPortCommand()
	networkscan.InitServiceCommand()

	if err := networkscan.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
