package service

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
)

func TestTCPHostnameTargets(t *testing.T) {
	host := "Product.Invalid."
	for _, tc := range []struct {
		name   string
		config discover.DiscoverServiceConfig
		want   []string
	}{
		{"default", discover.DiscoverServiceConfig{Targets: []string{"127.0.0.1:443"}}, []string{"127.0.0.1:443=127.0.0.1"}},
		{"global", discover.DiscoverServiceConfig{Targets: []string{"127.0.0.1:443", "[::1]:8443"}, Hostname: &host}, []string{"127.0.0.1:443=product.invalid", "[::1]:8443=product.invalid"}},
		{"bindings", discover.DiscoverServiceConfig{
			Targets: []string{"127.0.0.1:443", "127.0.0.1:8443", "[::1]:443"},
			TargetHostnames: []string{
				"127.0.0.1:443|one.invalid",
				"127.0.0.1:443|two.invalid",
				"127.0.0.1:443|ONE.INVALID.",
				"[0:0:0:0:0:0:0:1]:443|v6.invalid",
			},
		}, []string{"127.0.0.1:443=one.invalid", "127.0.0.1:443=two.invalid", "127.0.0.1:8443=127.0.0.1", "[::1]:443=v6.invalid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets, err := parseTCPServiceConfigTargets(tc.config)
			if err != nil || len(targets) != len(tc.want) {
				t.Fatalf("got %+v, %v", targets, err)
			}
			for i, target := range targets {
				got := net.JoinHostPort(target.ip.String(), strconv.Itoa(target.port)) + "=" + target.host
				if got != tc.want[i] {
					t.Errorf("got %q, want %q", got, tc.want[i])
				}
			}
		})
	}
}

func TestTCPHostnameValidation(t *testing.T) {
	for _, hostname := range []string{"", "https://example.com", "example.com:443", "127.0.0.1", "::1", "-bad.test", "bad-.test", "a..test", "a_test", "a\r\nHost: evil", " a.test", strings.Repeat("a", 64) + ".test"} {
		t.Run(hostname, func(t *testing.T) {
			_, err := parseTCPServiceConfigTargets(discover.DiscoverServiceConfig{Targets: []string{"127.0.0.1:443"}, Hostname: &hostname})
			if err == nil {
				t.Fatal("accepted invalid hostname")
			}
		})
	}
	host := "product.invalid"
	for _, target := range []string{"example.com:443", "127.0.0.1", "127.0.0.0/24:443", "127.0.0.1:0", "127.0.0.1:65536", "::1:443"} {
		if _, err := parseTCPServiceConfigTargets(discover.DiscoverServiceConfig{Targets: []string{target}, Hostname: &host}); err == nil {
			t.Errorf("accepted invalid socket %q", target)
		}
	}
	for _, config := range []discover.DiscoverServiceConfig{
		{Targets: []string{"127.0.0.1:443"}, TargetHostnames: []string{""}},
		{Targets: []string{"127.0.0.1:443"}, TargetHostnames: []string{"127.0.0.1:8443|" + host}},
		{Targets: []string{"127.0.0.1:443"}, Hostname: &host, TargetHostnames: []string{"127.0.0.1:443|" + host}},
	} {
		if _, err := parseTCPServiceConfigTargets(config); err == nil {
			t.Errorf("accepted invalid config %+v", config)
		}
	}
	for _, binding := range []string{"127.0.0.1:443", "127.0.0.1:443=product.invalid", "127.0.0.1:443|", "|product.invalid", "127.0.0.1:443|product.invalid|extra", "127.0.0.1:443|bad_name", "example.invalid:443|product.invalid"} {
		if _, err := parseTCPServiceConfigTargets(discover.DiscoverServiceConfig{Targets: []string{"127.0.0.1:443"}, TargetHostnames: []string{binding}}); err == nil {
			t.Errorf("accepted invalid binding %q", binding)
		}
	}
}

func TestTCPHostnameFlatConfig(t *testing.T) {
	const input = `{"targets":["127.0.0.1:443"],"timeout":2,"threads":1,"pluginThreads":1,"targetHostnames":["127.0.0.1:443|product.invalid"]}`
	var config discover.DiscoverServiceConfig
	if err := json.Unmarshal([]byte(input), &config); err != nil {
		t.Fatal(err)
	}
	targets, err := parseTCPServiceConfigTargets(config)
	if err != nil || len(targets) != 1 || targets[0].host != "product.invalid" || targets[0].ip.String() != "127.0.0.1" {
		t.Fatalf("invalid flat config: %+v, %v", targets, err)
	}
	output, err := json.Marshal(config)
	if err != nil || !strings.Contains(string(output), `"targetHostnames":["127.0.0.1:443|product.invalid"]`) {
		t.Fatalf("config did not stay flat: %s, %v", output, err)
	}
}

func TestTCPHostnameAndUserAgentStealth(t *testing.T) {
	var requests atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "product.invalid" || !strings.HasPrefix(r.Host, "product.invalid:") || r.UserAgent() != "curl/8.4.0" {
			t.Errorf("wrong request identity: Host=%q, SNI=%q, UA=%q", r.Host, r.TLS.ServerName, r.UserAgent())
		}
		requests.Add(1)
		w.Header().Set("Location", "https://not-contacted.invalid/")
		w.WriteHeader(http.StatusFound)
	}))
	defer s.Close()
	ua := common.UserAgentPresetCurl
	config := discover.DiscoverServiceConfig{Targets: []string{s.Listener.Addr().String()}, TargetHostnames: []string{s.Listener.Addr().String() + "|product.invalid"}, UserAgent: &ua, Stealth: &discover.ServiceStealthConfig{ServiceType: discover.StealthServiceTypeHttp}, Timeout: 2, Threads: 2, PluginThreads: 2}
	report, err := RunTCPServiceFingerprint(context.Background(), config)
	if err != nil || report.Result == nil || len(report.Result.Services) == 0 {
		t.Fatalf("missing service: %+v, %v", report, err)
	}
	if requests.Load() != 1 || report.Result.Services[0].Tls == nil || !*report.Result.Services[0].Tls {
		t.Fatalf("wrong HTTPS result: %+v, requests=%d", report.Result.Services, requests.Load())
	}
	if _, err := RunUDPServiceFingerprint(context.Background(), config); err == nil {
		t.Fatal("UDP accepted HTTP-only options")
	}
}
