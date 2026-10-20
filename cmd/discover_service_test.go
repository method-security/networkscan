package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
		{"chrome", []string{"--user-agent", "chrome"}, false},
		{"invalid-user-agent", []string{"--user-agent", "arbitrary-browser"}, true},
		{"empty-user-agent", []string{"--user-agent", ""}, true},
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
			err = setDiscoverServiceHTTPFlags(command, &config)
			if (err != nil) != tc.bad {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.name == "omitted" && (config.UserAgent == nil || *config.UserAgent != common.UserAgentPresetRandom) {
				t.Fatalf("missing RANDOM default: %+v", config)
			}
			if tc.name == "chrome" && (config.UserAgent == nil || *config.UserAgent != common.UserAgentPresetChrome) {
				t.Fatalf("wrong preset: %+v", config)
			}
			for _, name := range []string{"hostname", "target-hostnames"} {
				if command.Flags().Lookup(name) != nil {
					t.Errorf("unexpected separate hostname flag %q", name)
				}
			}
			udp, _, err := a.RootCmd.Find([]string{"discover", "service", "udp"})
			if err != nil {
				t.Fatal(err)
			}
			if udp.Flags().Lookup("user-agent") != nil {
				t.Error("HTTP-only user-agent flag exposed on UDP")
			}
		})
	}
}

func TestDiscoverServiceInlineHostname(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "product.invalid" || !strings.HasPrefix(r.Host, "product.invalid:") || r.UserAgent() != "curl/8.4.0" {
			t.Errorf("wrong identity: Host=%q SNI=%q UA=%q", r.Host, r.TLS.ServerName, r.UserAgent())
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()
	a := NewNetworkScan("test")
	a.InitRootCommand()
	a.InitDiscoverCommand()
	command, _, err := a.RootCmd.Find([]string{"discover", "service", "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	target := s.Listener.Addr().String() + "|product.invalid"
	command.SetContext(context.Background())
	if err := command.ParseFlags([]string{"--targets", target, "--service-type", "HTTP", "--user-agent", "CURL", "--timeout", "5"}); err != nil {
		t.Fatal(err)
	}
	a.runDiscoverServiceCommand(command, false)
	report, ok := a.OutputSignal.Content.(*discover.DiscoverServiceReport)
	if !ok || report.Result == nil || len(report.Result.Services) != 1 || report.Config.Targets[0] != target {
		t.Fatalf("missing inline target report: %+v", a.OutputSignal)
	}
	result := report.Result.Services[0]
	if result.Host != "product.invalid" || result.Ip != "127.0.0.1" || result.Tls == nil || !*result.Tls {
		t.Fatalf("incorrect result: %+v", result)
	}
}
