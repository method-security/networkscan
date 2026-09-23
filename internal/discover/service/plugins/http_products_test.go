package plugins

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

type nativeHTTPProductProbe interface {
	Name() string
	DefaultPorts() []int
	Detect(context.Context, net.IP, int, string, int) (*discover.ServiceDetails, error)
}

func nativeHTTPProductProbes() []nativeHTTPProductProbe {
	return []nativeHTTPProductProbe{HTTPDiscoveryFingerprinter{}, HTTPSFingerprinter{}, CouchDBFingerprinter{}, CouchDBTLSFingerprinter{}, ElasticsearchFingerprinter{}, InfluxDBFingerprinter{}, KubernetesFingerprinter{}, ChromaDBFingerprinter{}, ChromaDBTLSFingerprinter{}, MilvusFingerprinter{}, MilvusMetricsFingerprinter{}, PineconeFingerprinter{}}
}

func nativeHTTPProductPort(t *testing.T, addr net.Addr) int {
	t.Helper()
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	if !net.ParseIP(host).IsLoopback() {
		t.Fatalf("test endpoint is not loopback: %s", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestNativeHTTPProductInventory(t *testing.T) {
	names := []string{"http", "https", "couchdb", "couchdb", "elasticsearch", "influxdb", "kubernetes", "chromadb", "chromadb", "milvus", "milvus-metrics", "pinecone"}
	ports := [][]int{{80, 3000, 4567, 5000, 8000, 8001, 8080, 8081, 8888, 9001, 9080, 9090, 9100}, {443, 8443, 9443}, {5984}, {6984}, {9200}, {8086}, {6443}, {8000}, {8000}, {19530}, {9091}, {443}}
	for i, p := range nativeHTTPProductProbes() {
		if p.Name() != names[i] || !reflect.DeepEqual(p.DefaultPorts(), ports[i]) {
			t.Errorf("%T inventory: %s %v", p, p.Name(), p.DefaultPorts())
		}
	}
}

func TestNativeHTTPProductEvidence(t *testing.T) {
	for _, tc := range []struct {
		name                string
		probe               nativeHTTPProductProbe
		secure              bool
		path, body, version string
		headers             map[string]string
	}{
		{"http", HTTPDiscoveryFingerprinter{}, false, "/", "<html><title>Local fixture</title></html>", "fixture", map[string]string{"Server": "fixture"}},
		{"https", HTTPSFingerprinter{}, true, "/", "<html></html>", "fixture-tls", map[string]string{"Server": "fixture-tls"}},
		{"couch", CouchDBFingerprinter{}, false, "/", `{"couchdb":"Welcome","version":"3.9.2","uuid":"fixture","vendor":{"name":"Apache"}}`, "3.9.2", nil},
		{"couch-tls", CouchDBTLSFingerprinter{}, true, "/", `{"couchdb":"Welcome","version":"3.9.2"}`, "3.9.2", nil},
		{"elastic", ElasticsearchFingerprinter{}, false, "/", `{"cluster_name":"local","tagline":"You Know, for Search","version":{"number":"8.14.0","lucene_version":"9.10.0"}}`, "8.14.0", nil},
		{"elastic-tls", ElasticsearchFingerprinter{}, true, "/", `{}`, "", map[string]string{"X-Elastic-Product": "Elasticsearch"}},
		{"influx", InfluxDBFingerprinter{}, false, "/health", `{"name":"influxdb","status":"pass","version":"2.8.1","commit":"fixture"}`, "2.8.1", nil},
		{"influx-ping", InfluxDBFingerprinter{}, false, "/ping", "", "1.8.9", map[string]string{"X-Influxdb-Version": "1.8.9"}},
		{"influx-tls", InfluxDBFingerprinter{}, true, "/health", `{"name":"influxdb","status":"fail","version":"2.8.1"}`, "2.8.1", nil},
		{"kubernetes", KubernetesFingerprinter{}, true, "/version", `{"major":"1","minor":"33","gitVersion":"v1.33.2+k3s1","gitCommit":"fixture","goVersion":"go1.24","platform":"linux/amd64"}`, "v1.33.2+k3s1", nil},
		{"kubernetes-plain", KubernetesFingerprinter{}, false, "/version", `{"major":"1","minor":"33","gitVersion":"v1.33.2","gitCommit":"fixture"}`, "v1.33.2", nil},
		{"chroma", ChromaDBFingerprinter{}, false, "/api/v2/heartbeat", `{"nanosecond heartbeat":1790000000000000000}`, "1.2.0", nil},
		{"chroma-v1", ChromaDBFingerprinter{}, false, "/api/v1/heartbeat", `{"nanosecond heartbeat":1790000000000000000}`, "1.2.0", nil},
		{"chroma-tls", ChromaDBTLSFingerprinter{}, true, "/api/v2/heartbeat", `{"nanosecond heartbeat":1790000000000000000}`, "1.2.0", nil},
		{"metrics", MilvusMetricsFingerprinter{}, false, "/metrics", "# TYPE milvus_build_info gauge\nmilvus_build_info{version=\"2.5.9\",built=\"local test\"} 1\n", "2.5.9", nil},
		{"metrics-tls", MilvusMetricsFingerprinter{}, true, "/metrics", "milvus_build_info{version=\"2.5.9\"} 1\n", "2.5.9", nil},
		{"pinecone", PineconeFingerprinter{}, true, "/", `{"error":"authentication required"}`, "", map[string]string{"X-Pinecone-Api-Version": "2025-10"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var observed atomic.Bool
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.Host, "product.test:") {
					t.Errorf("wrong Host: %q", r.Host)
				}
				if tc.secure && (r.TLS == nil || r.TLS.ServerName != "product.test") {
					t.Errorf("missing SNI: %#v", r.TLS)
				}
				if r.Header.Get("Authorization") != "" || r.Header.Get("Api-Key") != "" {
					t.Error("unexpected credentials")
				}
				if r.URL.Path == "/api" {
					_, _ = io.WriteString(w, `{"kind":"APIVersions","apiVersion":"v1","versions":["v1"]}`)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/version") && tc.probe.Name() == "chromadb" {
					_, _ = io.WriteString(w, `"1.2.0"`)
					return
				}
				if r.URL.Path != tc.path {
					http.NotFound(w, r)
					return
				}
				observed.Store(true)
				for k, v := range tc.headers {
					w.Header().Set(k, v)
				}
				_, _ = io.WriteString(w, tc.body)
			}))
			if tc.secure {
				s.StartTLS()
			} else {
				s.Start()
			}
			defer s.Close()
			r, err := tc.probe.Detect(context.Background(), net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, s.Listener.Addr()), "product.test", 3)
			if err != nil || r == nil {
				t.Fatalf("no result: %v", err)
			}
			if !observed.Load() || r.Tls == nil || *r.Tls != tc.secure || r.Transport != common.TransportTypeTcp || r.Version == nil || *r.Version != tc.version {
				t.Fatalf("unexpected result: %+v", r)
			}
			m := r.Metadata.Generic.Metadata
			if m["application_protocol"] != tc.probe.Name() || m["responseHeaders"] == "" {
				t.Fatalf("missing metadata: %v", m)
			}
			if productCPEIdentity[tc.probe.Name()] != "" && !strings.Contains(m["cpes"], "cpe:2.3:a:"+productCPEIdentity[tc.probe.Name()]+":") {
				t.Fatalf("missing product CPE: %v", m)
			}
			if tc.name == "kubernetes" && (m["distribution"] != "k3s" || m["gitCommit"] != "fixture") {
				t.Fatalf("lost version metadata: %v", m)
			}
			if tc.name == "pinecone" && m["apiVersion"] != "2025-10" {
				t.Fatalf("lost API version: %v", m)
			}
		})
	}
}

func TestNativeHTTPProductKubernetesRestrictedAPI(t *testing.T) {
	for _, tc := range []struct {
		name           string
		code           int
		body           string
		invalidVersion bool
		match          bool
	}{
		{"forbidden", 403, `{"kind":"Status","apiVersion":"v1","reason":"Forbidden","status":"Failure","code":403}`, false, true},
		{"unauthorized", 401, `{"kind":"Status","apiVersion":"v1","reason":"Unauthorized","status":"Failure","code":401}`, false, true},
		{"generic-forbidden", 403, `{"error":"Forbidden","code":403}`, false, false},
		{"wrong-code", 403, `{"kind":"Status","apiVersion":"v1","reason":"Forbidden","status":"Failure","code":401}`, false, false},
		{"wrong-reason", 403, `{"kind":"Status","apiVersion":"v1","reason":"Unauthorized","status":"Failure","code":403}`, false, false},
		{"wrong-kind", 403, `{"kind":"Error","apiVersion":"v1","reason":"Forbidden","status":"Failure","code":403}`, false, false},
		{"wrong-api-version", 403, `{"kind":"Status","apiVersion":"v2","reason":"Forbidden","status":"Failure","code":403}`, false, false},
		{"missing-status", 403, `{"kind":"Status","apiVersion":"v1","reason":"Forbidden","code":403}`, false, false},
		{"string-code", 403, `{"kind":"Status","apiVersion":"v1","reason":"Forbidden","status":"Failure","code":"403"}`, false, false},
		{"invalid-version", 403, `{"kind":"Status","apiVersion":"v1","reason":"Forbidden","status":"Failure","code":403}`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/version":
					if tc.invalidVersion {
						_, _ = io.WriteString(w, `{"version":"1.33.2"}`)
						return
					}
					_, _ = io.WriteString(w, `{"major":"1","minor":"33","gitVersion":"v1.33.2","gitCommit":"fixture","platform":"linux/amd64"}`)
				case "/api":
					w.WriteHeader(tc.code)
					_, _ = io.WriteString(w, tc.body)
				default:
					http.NotFound(w, r)
				}
			}))
			defer s.Close()
			r, err := (KubernetesFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, s.Listener.Addr()), "product.test", 2)
			if err != nil || (r != nil) != tc.match {
				t.Fatalf("match=%v result=%+v error=%v", tc.match, r, err)
			}
			if r != nil && (r.Tls == nil || !*r.Tls || r.Transport != common.TransportTypeTcp || r.Version == nil || *r.Version != "v1.33.2" || r.Metadata.Generic.Metadata["gitCommit"] != "fixture") {
				t.Fatalf("lost version/TLS metadata: %+v", r)
			}
		})
	}
}

func TestNativeHTTPProductRejectsGenericResponses(t *testing.T) {
	for _, p := range nativeHTTPProductProbes()[2:] {
		t.Run(fmt.Sprintf("%T", p), func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Server", "envoy")
				_, _ = io.WriteString(w, `{"version":"1.2.3","status":"ok","error":"unauthorized"}`)
			}))
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			r, _ := p.Detect(ctx, net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, s.Listener.Addr()), "product.test", 2)
			if r != nil {
				t.Fatalf("generic JSON matched %T", p)
			}
		})
	}
}

func TestNativeHTTPProductCancellation(t *testing.T) {
	for _, p := range nativeHTTPProductProbes() {
		t.Run(fmt.Sprintf("%T", p), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			accepted := make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := listener.Accept()
				if err != nil {
					return
				}
				defer func() { _ = c.Close() }()
				close(accepted)
				_, _ = io.Copy(io.Discard, c)
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				r, err := p.Detect(ctx, net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, listener.Addr()), "product.test", 10)
				if r != nil {
					err = fmt.Errorf("matched silent peer")
				}
				result <- err
			}()
			select {
			case <-accepted:
			case <-time.After(2 * time.Second):
				t.Fatal("no local connection")
			}
			cancel()
			select {
			case err := <-result:
				if err == nil {
					t.Error("cancellation was not reported")
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not stop discovery")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("connection leaked")
			}
		})
	}
}

func TestNativeHTTPProductBoundsAndRedirects(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	for _, mode := range []string{"oversized", "redirect", "cancelled", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "oversized":
					_, _ = io.WriteString(w, strings.Repeat("x", productBodyLimit+1))
				case "redirect":
					http.Redirect(w, r, target.URL, http.StatusFound)
				case "timeout":
					<-r.Context().Done()
				}
			}))
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			p := newProductHTTP(net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, s.Listener.Addr()), "product.test", 1, false)
			defer p.transport.CloseIdleConnections()
			r, _, err := p.get(ctx, "/")
			if mode == "redirect" {
				if err != nil || r.StatusCode != 302 || redirected.Load() != 0 {
					t.Fatalf("redirect followed: %v", err)
				}
			} else if err == nil {
				t.Fatal("expected bounded request error")
			}
		})
	}
}

func TestNativeHTTPProductMilvusGRPC(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply []byte
		code  codes.Code
		match bool
	}{
		{"version", []byte{0x0a, 0, 0x12, 5, '2', '.', '5', '.', '7'}, codes.OK, true},
		{"empty", nil, codes.OK, false},
		{"failed-status", []byte{0x0a, 2, 0x08, 1, 0x12, 3, '2', '.', '5'}, codes.OK, false},
		{"truncated", []byte{0x0a, 0, 0x12, 100, '2'}, codes.OK, false},
		{"unauthenticated", nil, codes.Unauthenticated, false},
		{"oversized", make([]byte, productBodyLimit+1), codes.OK, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			s := grpc.NewServer(grpc.ForceServerCodec(milvusVersionCodec{}), grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
				method, _ := grpc.MethodFromServerStream(stream)
				if method != "/milvus.proto.milvus.MilvusService/GetVersion" {
					return status.Error(codes.Unimplemented, "unknown")
				}
				var request []byte
				if err := stream.RecvMsg(&request); err != nil {
					return err
				}
				if len(request) != 0 {
					return status.Error(codes.InvalidArgument, "request not empty")
				}
				if tc.code != codes.OK {
					return status.Error(tc.code, "fixture error")
				}
				return stream.SendMsg(&tc.reply)
			}))
			go func() { _ = s.Serve(listener) }()
			defer s.Stop()
			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			r, err := (MilvusFingerprinter{}).Detect(ctx, net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, listener.Addr()), "product.test", 2)
			if (r != nil) != tc.match {
				t.Fatalf("match=%v result=%+v err=%v", tc.match, r, err)
			}
			if tc.match && (*r.Version != "2.5.7" || *r.Tls || r.Transport != common.TransportTypeTcp) {
				t.Fatalf("wrong metadata: %+v", r)
			}
		})
	}
}

func TestNativeHTTPProductChromaGRPC(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, name := range []string{"chroma.SysDB", "unrelated.SysDB"} {
			t.Run(fmt.Sprintf("%s/tls=%v", name, secure), func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				var options []grpc.ServerOption
				if secure {
					certServer := httptest.NewTLSServer(http.NotFoundHandler())
					config := &tls.Config{Certificates: certServer.TLS.Certificates, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
						if hello.ServerName != "product.test" {
							t.Errorf("wrong grpc SNI: %s", hello.ServerName)
						}
						return nil, nil
					}}
					certServer.Close()
					options = append(options, grpc.Creds(credentials.NewTLS(config)))
				}
				s := grpc.NewServer(options...)
				s.RegisterService(&grpc.ServiceDesc{ServiceName: name, HandlerType: (*interface{})(nil)}, struct{}{})
				reflection.Register(s)
				go func() { _ = s.Serve(listener) }()
				defer s.Stop()
				var p nativeHTTPProductProbe = ChromaDBFingerprinter{}
				if secure {
					p = ChromaDBTLSFingerprinter{}
				}
				r, err := p.Detect(context.Background(), net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, listener.Addr()), "product.test", 2)
				if (r != nil) != (name == "chroma.SysDB") {
					t.Fatalf("unexpected result: %+v %v", r, err)
				}
				if r != nil && (*r.Tls != secure || r.Metadata.Generic.Metadata["rpcService"] != name) {
					t.Fatalf("wrong metadata: %+v", r)
				}
			})
		}
	}
}

func TestNativeHTTPProductMetricsRejectsText(t *testing.T) {
	for _, body := range []string{"# HELP milvus_build_info version=\"2.0\"\n", "other_metric{product=\"milvus_build_info\"} 1\n", "milvus_build_info{version=\"2.0\"} garbage\n", "milvus_build_info{version=\"2.0\"} 0\n"} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
		r, _ := (MilvusMetricsFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, s.Listener.Addr()), "product.test", 1)
		s.Close()
		if r != nil {
			t.Fatalf("matched %q", body)
		}
	}
}

type nativeHTTPProductConnStats struct{ ended chan struct{} }

func (*nativeHTTPProductConnStats) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}
func (*nativeHTTPProductConnStats) HandleRPC(context.Context, stats.RPCStats) {}
func (*nativeHTTPProductConnStats) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}
func (s *nativeHTTPProductConnStats) HandleConn(_ context.Context, event stats.ConnStats) {
	if _, ok := event.(*stats.ConnEnd); ok {
		select {
		case s.ended <- struct{}{}:
		default:
		}
	}
}

func TestNativeHTTPProductGRPCConnectionLifetime(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%v", secure), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			tracker := &nativeHTTPProductConnStats{ended: make(chan struct{}, 1)}
			options := []grpc.ServerOption{grpc.StatsHandler(tracker), grpc.ForceServerCodec(milvusVersionCodec{}), grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
				var request []byte
				if err := stream.RecvMsg(&request); err != nil {
					return err
				}
				response := []byte{0x0a, 0, 0x12, 3, '2', '.', '7'}
				return stream.SendMsg(&response)
			})}
			if secure {
				certServer := httptest.NewTLSServer(http.NotFoundHandler())
				options = append(options, grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: certServer.TLS.Certificates})))
				certServer.Close()
			}
			s := grpc.NewServer(options...)
			go func() { _ = s.Serve(listener) }()
			defer s.Stop()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cc, err := productGRPC(ctx, net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, listener.Addr()), "product.test", 3, secure)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cc.Close() }()
			// Both calls run after the dialer returned; neither may lose its socket
			// when gRPC cancels the temporary dial context.
			for i := 0; i < 2; i++ {
				var request, response []byte
				if err := cc.Invoke(ctx, "/milvus.proto.milvus.MilvusService/GetVersion", &request, &response, grpc.ForceCodec(milvusVersionCodec{})); err != nil {
					t.Fatal(err)
				}
				if version, ok := milvusVersion(response); !ok || version != "2.7" {
					t.Fatalf("invalid reply: %x", response)
				}
			}
			cancel()
			select {
			case <-tracker.ended:
			case <-time.After(time.Second):
				t.Fatal("parent cancellation did not close established socket")
			}
		})
	}
}
