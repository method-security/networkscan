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
	for _, tc := range []struct {
		name    string
		targets []string
		want    []string
	}{
		{"default", []string{"127.0.0.1:443", "[::1]:8443"}, []string{"127.0.0.1:443|127.0.0.1", "[::1]:8443|::1"}},
		{"hostname", []string{"127.0.0.1:443|Product.Invalid.", "[::1]:8443|product.invalid"}, []string{"127.0.0.1:443|Product.Invalid.", "[::1]:8443|product.invalid"}},
		{"mixed", []string{"127.0.0.1:443|one.invalid", "127.0.0.1:443|two.invalid", "127.0.0.1:443|ONE.INVALID.", "127.0.0.1:443|one.invalid", "127.0.0.1:8443", "[0:0:0:0:0:0:0:1]:443|v6.invalid"}, []string{"127.0.0.1:443|one.invalid", "127.0.0.1:443|two.invalid", "127.0.0.1:443|ONE.INVALID.", "127.0.0.1:8443|127.0.0.1", "[::1]:443|v6.invalid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets, err := parseTCPServiceTargets(tc.targets)
			if err != nil || len(targets) != len(tc.want) {
				t.Fatalf("got %+v, %v", targets, err)
			}
			for i, target := range targets {
				got := net.JoinHostPort(target.ip.String(), strconv.Itoa(target.port)) + "|" + target.host
				if got != tc.want[i] {
					t.Errorf("got %q, want %q", got, tc.want[i])
				}
			}
		})
	}
}

func TestTCPHostnamePreserved(t *testing.T) {
	for _, hostname := range []string{"Product.Invalid.", "https://example.com", "example.com:443", "127.0.0.1", "::1", "-bad.test", "bad-.test", "a..test", "a_test", "a\r\nHost: evil", " a.test ", strings.Repeat("a", 64) + ".test", strings.Repeat("a.", 127) + "test"} {
		t.Run(hostname, func(t *testing.T) {
			targets, err := parseTCPServiceTargets([]string{"127.0.0.1:443|" + hostname})
			if err != nil || len(targets) != 1 {
				t.Fatalf("got %+v, %v", targets, err)
			}
			if targets[0].host != hostname {
				t.Fatalf("got hostname %q, want %q", targets[0].host, hostname)
			}
		})
	}
}

func TestTCPHostnameTargetStructure(t *testing.T) {
	for _, target := range []string{"example.com:443", "127.0.0.1", "127.0.0.0/24:443", "127.0.0.1:0", "127.0.0.1:65536", "::1:443"} {
		if _, err := parseTCPServiceTargets([]string{target + "|product.invalid"}); err == nil {
			t.Errorf("accepted invalid socket %q", target)
		}
	}
	for _, target := range []string{"127.0.0.1:443", "127.0.0.1:443=product.invalid", "127.0.0.1:443|", "|product.invalid", "127.0.0.1:443|product.invalid|extra"} {
		if _, err := parseTCPHostnameTarget(target); err == nil {
			t.Errorf("accepted invalid hostname target %q", target)
		}
	}
}

func TestTCPHostnameFlatConfig(t *testing.T) {
	const input = `{"targets":["127.0.0.1:443|product.invalid"],"timeout":2,"threads":1,"pluginThreads":1}`
	var config discover.DiscoverServiceConfig
	if err := json.Unmarshal([]byte(input), &config); err != nil {
		t.Fatal(err)
	}
	targets, err := parseTCPServiceTargets(config.Targets)
	if err != nil || len(targets) != 1 || targets[0].host != "product.invalid" || targets[0].ip.String() != "127.0.0.1" {
		t.Fatalf("invalid flat config: %+v, %v", targets, err)
	}
	output, err := json.Marshal(config)
	if err != nil || !strings.Contains(string(output), `"targets":["127.0.0.1:443|product.invalid"]`) || strings.Contains(string(output), "targetHostnames") || strings.Contains(string(output), `"hostname"`) {
		t.Fatalf("config did not stay flat: %s, %v", output, err)
	}
}

func TestTCPHostnameAndUserAgentStealth(t *testing.T) {
	const hostname = "Product.Invalid"
	var requests atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != hostname || !strings.HasPrefix(r.Host, hostname+":") || r.UserAgent() != "curl/8.4.0" {
			t.Errorf("wrong request identity: Host=%q, SNI=%q, UA=%q", r.Host, r.TLS.ServerName, r.UserAgent())
		}
		requests.Add(1)
		w.Header().Set("Location", "https://not-contacted.invalid/")
		w.WriteHeader(http.StatusFound)
	}))
	defer s.Close()
	ua := common.UserAgentPresetCurl
	config := discover.DiscoverServiceConfig{Targets: []string{s.Listener.Addr().String() + "|" + hostname}, UserAgent: &ua, Stealth: &discover.ServiceStealthConfig{ServiceType: discover.StealthServiceTypeHttp}, Timeout: 5, Threads: 2, PluginThreads: 2}
	report, err := RunTCPServiceFingerprint(context.Background(), config)
	if err != nil || report.Result == nil || len(report.Result.Services) == 0 {
		t.Fatalf("missing service: %+v, %v", report, err)
	}
	if requests.Load() != 1 || report.Result.Services[0].Tls == nil || !*report.Result.Services[0].Tls || report.Result.Services[0].Host != hostname || report.Result.Services[0].Ip != "127.0.0.1" {
		t.Fatalf("wrong HTTPS result: %+v, requests=%d", report.Result.Services, requests.Load())
	}
	if _, err := RunUDPServiceFingerprint(context.Background(), config); err == nil {
		t.Fatal("UDP accepted HTTP user agent")
	}
	config.UserAgent = nil
	if _, err := RunUDPServiceFingerprint(context.Background(), config); err == nil {
		t.Fatal("UDP accepted hostname target")
	}
}

func TestTCPHostnameRandomUserAgentFallback(t *testing.T) {
	userAgents := make(chan string, 2)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgents <- r.UserAgent()
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()
	address := s.Listener.Addr().String()
	config := discover.DiscoverServiceConfig{
		Targets:       []string{address + "|one.invalid", address + "|two.invalid"},
		Stealth:       &discover.ServiceStealthConfig{ServiceType: discover.StealthServiceTypeHttp},
		Timeout:       5,
		Threads:       2,
		PluginThreads: 2,
	}
	report, err := RunTCPServiceFingerprint(context.Background(), config)
	if err != nil || report.Result == nil || len(report.Result.Services) != 2 {
		t.Fatalf("missing services: %+v, %v", report, err)
	}
	if report.Config.UserAgent == nil || *report.Config.UserAgent != common.UserAgentPresetRandom {
		t.Fatalf("missing RANDOM config default: %+v", report.Config)
	}
	if len(userAgents) != 2 {
		t.Fatalf("got %d requests, want 2", len(userAgents))
	}
	first, second := <-userAgents, <-userAgents
	if first == "" || strings.HasPrefix(first, "Go-http-client/") || strings.HasPrefix(first, "networkscan") {
		t.Fatalf("no random user agent selected: %q", first)
	}
	if first != second {
		t.Fatalf("user agent changed within a scan: %q != %q", first, second)
	}
}
