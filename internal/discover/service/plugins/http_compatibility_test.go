package plugins

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPDiscoveryMalformedRedirect(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%v", secure), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "https://"+r.Host+":4343/")
				w.WriteHeader(http.StatusFound)
			}))
			if secure {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			result, err := discoverNativeHTTP(context.Background(), net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, server.Listener.Addr()), "redirect.test", 3, secure)
			if err != nil || result == nil {
				t.Fatalf("valid redirect response lost: %v", err)
			}
			if result.Metadata.Generic.Metadata["statusCode"] != "302" || result.Tls == nil || *result.Tls != secure {
				t.Fatalf("incorrect redirect metadata: %+v", result)
			}
		})
	}
}

func TestHTTPDiscoveryLegacyTLS(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS12} {
		t.Run(fmt.Sprintf("version=%x", version), func(t *testing.T) {
			cipher := tls.TLS_RSA_WITH_AES_256_GCM_SHA384
			if version == tls.VersionTLS10 {
				cipher = tls.TLS_RSA_WITH_AES_128_CBC_SHA
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS.Version != version || r.TLS.CipherSuite != cipher || r.TLS.ServerName != "legacy.test" {
					t.Errorf("unexpected TLS negotiation: %+v", r.TLS)
				}
				w.WriteHeader(http.StatusOK)
			}))
			server.TLS = &tls.Config{MinVersion: version, MaxVersion: version, CipherSuites: []uint16{cipher}} //nolint:gosec // Local compatibility fixture.
			server.StartTLS()
			defer server.Close()
			result, err := (HTTPSFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, server.Listener.Addr()), "legacy.test", 3)
			if err != nil || result == nil {
				t.Fatalf("legacy TLS service not detected: %v", err)
			}
		})
	}
}

func TestHTTPDiscoveryAuthority(t *testing.T) {
	for _, tc := range []struct {
		host   string
		port   int
		secure bool
		want   string
	}{
		{"service.test", 80, false, "service.test"},
		{"service.test", 443, true, "service.test"},
		{"service.test", 8080, false, "service.test:8080"},
		{"::1", 443, true, "[::1]"},
		{"::1", 8443, true, "[::1]:8443"},
	} {
		p := newProductHTTP(net.ParseIP("127.0.0.1"), tc.port, tc.host, 1, tc.secure)
		if p.base.Host != tc.want {
			t.Errorf("authority=%q want=%q", p.base.Host, tc.want)
		}
	}
}
