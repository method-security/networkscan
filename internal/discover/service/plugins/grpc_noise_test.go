package plugins

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func grpcNoiseServer(t *testing.T, secure bool, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	if secure {
		server.EnableHTTP2 = true
		server.StartTLS()
	} else {
		server.Config.Handler = h2c.NewHandler(handler, &http2.Server{})
		server.Start()
	}
	t.Cleanup(server.Close)
	return server
}

func TestGRPCNoiseProtocolEvidence(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, fixture := range []struct {
			name        string
			status      int
			contentType string
			grpcStatus  string
			trailers    bool
			want        bool
		}{
			{name: "ordinary-404", status: 404, contentType: "text/plain"},
			{name: "404-with-grpc-status", status: 404, contentType: "text/plain", grpcStatus: "12"},
			{name: "missing-content-type", status: 404, grpcStatus: "12"},
			{name: "invalid-content-type", status: 200, contentType: "application/grpc-impostor", grpcStatus: "12"},
			{name: "missing-grpc-status", status: 200, contentType: "application/grpc"},
			{name: "404-grpc-content-type-without-status", status: 404, contentType: "application/grpc"},
			{name: "trailers-only-disabled", status: 200, contentType: "application/grpc", grpcStatus: "12", want: true},
			{name: "separate-trailers-disabled", status: 200, contentType: "application/grpc", grpcStatus: "12", trailers: true, want: true},
		} {
			t.Run(fmt.Sprintf("tls=%t/%s", secure, fixture.name), func(t *testing.T) {
				t.Parallel()
				server := grpcNoiseServer(t, secure, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.ProtoMajor != 2 {
						t.Errorf("request protocol = %s", r.Proto)
					}
					w.Header()["Content-Type"] = nil
					if fixture.contentType != "" {
						w.Header().Set("Content-Type", fixture.contentType)
					}
					if fixture.trailers {
						w.Header().Set("Trailer", "Grpc-Status")
					} else if fixture.grpcStatus != "" {
						w.Header().Set("Grpc-Status", fixture.grpcStatus)
					}
					w.WriteHeader(fixture.status)
					if fixture.trailers {
						w.(http.Flusher).Flush()
						w.Header().Set("Grpc-Status", fixture.grpcStatus)
					}
				}))
				result, err := (GrpcFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), server.Listener.Addr().(*net.TCPAddr).Port, "loopback.test", 2)
				if err != nil {
					t.Fatal(err)
				}
				if (result != nil) != fixture.want {
					t.Fatalf("result = %+v, want detection %t", result, fixture.want)
				}
				if result != nil && (result.Protocol != common.ProtocolTypeGrpc || result.Tls == nil || *result.Tls != secure || result.Metadata.Grpc.ReflectionSupported) {
					t.Fatalf("unexpected metadata: %+v", result)
				}
			})
		}
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("tls=%t/real-server/reflection=%t", secure, enabled), func(t *testing.T) {
				t.Parallel()
				service := grpc.NewServer()
				if enabled {
					reflection.Register(service)
				}
				t.Cleanup(service.Stop)
				server := grpcNoiseServer(t, secure, service)
				result, err := (GrpcFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), server.Listener.Addr().(*net.TCPAddr).Port, "loopback.test", 2)
				if err != nil || result == nil {
					t.Fatalf("result = %+v, error = %v", result, err)
				}
				if result.Protocol != common.ProtocolTypeGrpc || result.Tls == nil || *result.Tls != secure || result.Metadata.Grpc.ReflectionSupported != enabled {
					t.Fatalf("unexpected metadata: %+v", result)
				}
			})
		}
	}
}

func TestGRPCNoiseDeadline(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%t", secure), func(t *testing.T) {
			server := grpcNoiseServer(t, secure, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			start := time.Now()
			result, err := (GrpcFingerprinter{}).Detect(ctx, net.ParseIP("127.0.0.1"), server.Listener.Addr().(*net.TCPAddr).Port, "loopback.test", 2)
			if result != nil || err != nil {
				t.Fatalf("result = %+v, error = %v", result, err)
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("parent deadline exceeded: %s", elapsed)
			}
		})
	}
}
