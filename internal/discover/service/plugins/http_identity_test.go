package plugins

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
)

func TestHTTPProbeRequestIdentity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		probe interface {
			Detect(context.Context, net.IP, int, string, int) (*discover.ServiceDetails, error)
		}
		defaultUA string
	}{
		{"http", HTTPDiscoveryFingerprinter{}, "networkscan"},
		{"https", HTTPSFingerprinter{}, "networkscan"},
		{"stealth-http", HTTPFingerprinter{}, "Go-http-client/1.1"},
		{"etcd", EtcdFingerprinter{}, "Go-http-client/1.1"},
		{"winrm", WinRMFingerprinter{}, "networkscan"},
		{"ipp", IPPFingerprinter{}, "networkscan-ipp"},
	} {
		for _, override := range []bool{false, true} {
			name := tc.name + "/default"
			ctx, wantUA := context.Background(), tc.defaultUA
			if override {
				name = tc.name + "/override"
				wantUA = "browser-fixture/1.0"
				ctx = helpers.WithHTTPUserAgent(ctx, wantUA)
			}
			t.Run(name, func(t *testing.T) {
				var requests atomic.Int32
				s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					ua := wantUA
					if tc.name == "winrm" && r.Method == http.MethodGet && !override {
						ua = "Go-http-client/1.1"
					}
					if r.UserAgent() != ua || !strings.HasPrefix(r.Host, "product.invalid:") {
						t.Errorf("wrong identity: Host=%q UA=%q, want UA=%q", r.Host, r.UserAgent(), ua)
					}
					if tc.name != "http" && (r.TLS == nil || r.TLS.ServerName != "product.invalid") {
						t.Errorf("wrong SNI: %+v", r.TLS)
					}
					switch tc.name {
					case "etcd":
						if r.URL.Path == "/version" {
							_, _ = io.WriteString(w, `{"etcdserver":"3.5.0","etcdcluster":"3.5.0"}`)
						} else {
							_, _ = io.WriteString(w, "etcd_server_is_leader 1\n")
						}
					case "winrm":
						if r.Method == http.MethodPost {
							w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
							w.Header().Set("WWW-Authenticate", "Negotiate")
							w.WriteHeader(http.StatusUnauthorized)
						} else {
							w.Header().Set("Allow", "POST")
							w.WriteHeader(http.StatusMethodNotAllowed)
						}
					case "ipp":
						_, _ = w.Write([]byte{1, 1, 0, 0})
					default:
						w.WriteHeader(http.StatusOK)
					}
				}))
				if tc.name == "http" {
					s.Start()
				} else {
					s.StartTLS()
				}
				defer s.Close()
				r, err := tc.probe.Detect(ctx, net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, s.Listener.Addr()), "product.invalid", 10)
				if err != nil || r == nil {
					t.Fatalf("missing service: %+v, %v", r, err)
				}
				wantRequests := int32(1)
				if tc.name == "etcd" || tc.name == "winrm" {
					wantRequests = 2
				}
				if requests.Load() != wantRequests {
					t.Fatalf("got %d requests, want %d", requests.Load(), wantRequests)
				}
			})
		}
	}
}

func TestGRPCHostnameWithoutBrowserUserAgent(t *testing.T) {
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer certServer.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: certServer.TLS.Certificates,
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				if hello.ServerName != "product.invalid" {
					t.Errorf("wrong gRPC SNI: %q", hello.ServerName)
				}
				return nil, nil
			},
		})),
		grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			md, _ := metadata.FromIncomingContext(stream.Context())
			if values := md.Get(":authority"); len(values) != 1 || values[0] != "product.invalid" {
				t.Errorf("wrong gRPC authority: %v", values)
			}
			if values := md.Get("user-agent"); len(values) != 1 || !strings.HasPrefix(values[0], "grpc-go/") {
				t.Errorf("browser user agent applied to gRPC: %v", values)
			}
			requests.Add(1)
			return handler(srv, stream)
		}),
	)
	reflection.Register(server)
	defer server.Stop()
	go func() { _ = server.Serve(listener) }()
	ctx := helpers.WithHTTPUserAgent(context.Background(), "browser-fixture")
	r, err := (GrpcFingerprinter{}).Detect(ctx, net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, listener.Addr()), "product.invalid", 3)
	if err != nil || r == nil || r.Tls == nil || !*r.Tls || requests.Load() == 0 {
		t.Fatalf("missing gRPC TLS result: %+v, %v", r, err)
	}
}

func TestMongoHTTPWarningIdentity(t *testing.T) {
	for _, override := range []bool{false, true} {
		ctx, host, wantUA := context.Background(), "127.0.0.1", ""
		if override {
			ctx, host, wantUA = helpers.WithHTTPUserAgent(ctx, "browser-fixture"), "product.invalid", "browser-fixture"
		}
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.UserAgent() != wantUA || (override && !strings.HasPrefix(r.Host, "product.invalid:")) {
				t.Errorf("wrong diagnostic request: Host=%q, UA=%q", r.Host, r.UserAgent())
			}
			_, _ = io.WriteString(w, "It looks like you are trying to access MongoDB over HTTP on the native driver port.")
		}))
		response, err := mongoHTTPWarningExchange(ctx, net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, s.Listener.Addr()), host, 1, false)
		s.Close()
		if err != nil || !strings.Contains(string(response), "MongoDB") {
			t.Fatalf("missing warning: %q, %v", response, err)
		}
	}
}

func TestHTTPSRequiresHTTPResponse(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := (HTTPSFingerprinter{}).Detect(ctx, net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, s.Listener.Addr()), "product.invalid", 1)
	if r != nil {
		t.Fatalf("TLS-only endpoint classified as HTTPS: %+v, %v", r, err)
	}
}

func TestNativeHTTPProductUserAgent(t *testing.T) {
	for _, probe := range nativeHTTPProductProbes() {
		// Milvus uses gRPC reflection, not HTTP. Its metrics probe is HTTP.
		if _, ok := probe.(MilvusFingerprinter); ok {
			continue
		}
		t.Run(probe.Name(), func(t *testing.T) {
			var requests atomic.Int32
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.UserAgent() != "browser-fixture" {
					t.Errorf("wrong user agent: %q", r.UserAgent())
				}
				if probe.Name() == "chromadb" {
					if strings.HasSuffix(r.URL.Path, "/heartbeat") {
						_, _ = io.WriteString(w, `{"nanosecond heartbeat":1234}`)
					} else {
						_, _ = io.WriteString(w, `"1.2.0"`)
					}
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			secure := false
			switch probe.(type) {
			case HTTPSFingerprinter, CouchDBTLSFingerprinter, ChromaDBTLSFingerprinter, KubernetesFingerprinter, PineconeFingerprinter:
				secure = true
			}
			if secure {
				s.StartTLS()
			} else {
				s.Start()
			}
			defer s.Close()
			ctx := helpers.WithHTTPUserAgent(context.Background(), "browser-fixture")
			_, _ = probe.Detect(ctx, net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, s.Listener.Addr()), "product.invalid", 5)
			if requests.Load() == 0 {
				t.Fatal("no HTTP requests observed")
			}
		})
	}
}
