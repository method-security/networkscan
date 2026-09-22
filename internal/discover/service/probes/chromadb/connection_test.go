package chromadb

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestChromaDBVersionUsesFreshConnection(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, versionBody := range []string{"", `{"version":"1.4.0-alpha"}`, `"1.4.0-alpha"`} {
			versionAvailable := versionBody != ""
			t.Run(fmt.Sprintf("tls=%v/version=%s", secure, versionBody), func(t *testing.T) {
				var connections, versions atomic.Int32
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Host != net.JoinHostPort("chroma.test", fmt.Sprint(r.Context().Value(http.LocalAddrContextKey).(net.Addr).(*net.TCPAddr).Port)) {
						t.Errorf("wrong Host: %s", r.Host)
					}
					if secure && (r.TLS == nil || r.TLS.ServerName != "chroma.test") {
						t.Error("missing TLS SNI")
					}
					w.Header().Set("Connection", "close")
					w.Header().Set("Content-Type", "application/json")
					body := `{"nanosecond heartbeat":1700000000000000000}`
					if r.URL.Path == "/api/v1/version" {
						versions.Add(1)
						if !versionAvailable {
							w.WriteHeader(http.StatusForbidden)
							return
						}
						body = versionBody
					} else if r.URL.Path != "/api/v1/heartbeat" {
						t.Errorf("unexpected path: %s", r.URL.Path)
					}
					// Chunked, fragmented bodies must be consumed completely before parsing.
					_, _ = w.Write([]byte(body[:len(body)/2]))
					w.(http.Flusher).Flush()
					_, _ = w.Write([]byte(body[len(body)/2:]))
				}))
				server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateNew {
						connections.Add(1)
					}
				}
				if secure {
					server.StartTLS()
				} else {
					server.Start()
				}
				defer server.Close()
				port := server.Listener.Addr().(*net.TCPAddr).Port
				plugin := &ChromaDBPlugin{}
				detect := plugin.Detect
				if secure {
					detect = (&ChromaDBTLSPlugin{}).Detect
				}
				result, err := detect(context.Background(), net.ParseIP("127.0.0.1"), port, "chroma.test", 2)
				if err != nil || result == nil {
					t.Fatalf("result=%+v err=%v", result, err)
				}
				want := ""
				if versionAvailable {
					want = "1.4.0"
				}
				if result.Version == nil || *result.Version != want {
					t.Fatalf("version=%v want=%q", result.Version, want)
				}
				if versions.Load() != 1 || connections.Load() != 2 {
					t.Fatalf("version requests=%d connections=%d", versions.Load(), connections.Load())
				}
				if result.Tls == nil || *result.Tls != secure {
					t.Fatalf("wrong TLS metadata: %+v", result)
				}
				if result.Metadata.Generic.Metadata["cpes"] != "["+buildChromaDBCPE(want)+"]" {
					t.Fatalf("wrong CPE: %+v", result.Metadata)
				}
			})
		}
	}
}

func TestChromaDBEnrichmentRespectsParentContext(t *testing.T) {
	var versionRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		if r.URL.Path == "/api/v1/version" {
			versionRequests.Add(1)
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte(`{"nanosecond heartbeat":1700000000000000000}`))
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _ = (&ChromaDBPlugin{}).Detect(ctx, net.ParseIP("127.0.0.1"), server.Listener.Addr().(*net.TCPAddr).Port, "chroma.test", 2)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("parent cancellation ignored: %s", elapsed)
	}
	if versionRequests.Load() != 1 {
		t.Fatal("version enrichment not exercised")
	}
}

func TestChromaDBResponseLimits(t *testing.T) {
	for _, oversizedHeader := range []bool{false, true} {
		t.Run(fmt.Sprintf("header=%v", oversizedHeader), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Connection", "close")
				if oversizedHeader {
					w.Header().Set("X-Padding", strings.Repeat("a", 2<<20))
					_, _ = w.Write([]byte(`{"nanosecond heartbeat":1700000000000000000}`))
				} else {
					_, _ = w.Write([]byte(strings.Repeat("a", (1<<20)+1)))
				}
			}))
			defer server.Close()
			result, err := (&ChromaDBPlugin{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), server.Listener.Addr().(*net.TCPAddr).Port, "chroma.test", 2)
			if result != nil || err == nil {
				t.Fatalf("accepted oversized response: result=%+v err=%v", result, err)
			}
		})
	}
}
