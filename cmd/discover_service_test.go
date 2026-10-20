package cmd

import (
	"testing"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
)

func TestDiscoverServiceHTTPFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		bad  bool
	}{
		{"omitted", nil, false},
		{"hostname", []string{"--hostname", "product.test", "--user-agent", "chrome"}, false},
		{"multiple-bindings", []string{"--target-hostnames", "127.0.0.1:443=one.test,127.0.0.2:443=two.test", "--target-hostnames", "127.0.0.1:443=three.test", "--user-agent", "CURL"}, false},
		{"mutually-exclusive", []string{"--hostname", "product.test", "--target-hostnames", "127.0.0.1:443=product.test"}, true},
		{"invalid-user-agent", []string{"--user-agent", "arbitrary-browser"}, true},
		{"empty-user-agent", []string{"--user-agent", ""}, true},
		{"invalid-binding", []string{"--target-hostnames", "127.0.0.1:443"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewNetworkScan("test")
			a.InitRootCommand()
			a.InitDiscoverCommand()
			command, _, err := a.RootCmd.Find([]string{"discover", "service", "tcp"})
			if err != nil {
				t.Fatal(err)
			}
			if err := command.ParseFlags(tc.args); err != nil {
				t.Fatal(err)
			}
			var config discover.DiscoverServiceConfig
			err = command.ValidateFlagGroups()
			if err == nil {
				err = setDiscoverServiceHTTPFlags(command, &config)
			}
			if (err != nil) != tc.bad {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.bad {
				return
			}
			switch tc.name {
			case "omitted":
				if config.UserAgent != nil || config.Hostname != nil || len(config.TargetHostnames) != 0 {
					t.Fatalf("changed defaults: %+v", config)
				}
			case "hostname":
				if config.Hostname == nil || *config.Hostname != "product.test" || config.UserAgent == nil || *config.UserAgent != common.UserAgentPresetChrome {
					t.Fatalf("wrong config: %+v", config)
				}
			case "multiple-bindings":
				if len(config.TargetHostnames) != 3 || config.TargetHostnames[2].Hostname != "three.test" || config.UserAgent == nil || *config.UserAgent != common.UserAgentPresetCurl {
					t.Fatalf("wrong config: %+v", config)
				}
			}
			udp, _, err := a.RootCmd.Find([]string{"discover", "service", "udp"})
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"user-agent", "hostname", "target-hostnames"} {
				if udp.Flags().Lookup(name) != nil {
					t.Errorf("HTTP-only flag %q exposed on UDP", name)
				}
			}
		})
	}
}
