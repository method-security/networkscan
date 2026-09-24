package plugins

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNativeHTTPDetectsValidHeadersWithIncompleteBody(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, oversized := range []bool{false, true} {
			t.Run(fmt.Sprintf("TLS=%v/oversized=%v", secure, oversized), func(t *testing.T) {
				handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Server", "local-fixture")
					if oversized {
						_, _ = io.WriteString(w, strings.Repeat("x", productBodyLimit+1))
					} else {
						w.Header().Set("Content-Length", "100")
						_, _ = io.WriteString(w, "partial")
					}
				})
				server := httptest.NewUnstartedServer(handler)
				if secure {
					server.StartTLS()
				} else {
					server.Start()
				}
				defer server.Close()
				result, err := discoverNativeHTTP(context.Background(), net.ParseIP("127.0.0.1"), server.Listener.Addr().(*net.TCPAddr).Port, "http.test", 3, secure)
				if err != nil || result == nil {
					t.Fatalf("valid HTTP headers not detected: %v", err)
				}
				if result.Metadata.Generic.Metadata["bodyIncomplete"] != "true" || result.Host != "http.test" || result.Tls == nil || *result.Tls != secure {
					t.Fatalf("incorrect detection: %+v", result)
				}
				if oversized && result.Metadata.Generic.Metadata["analysisTruncated"] != "true" {
					t.Fatal("large body was not bounded for technology analysis")
				}
			})
		}
	}
}
