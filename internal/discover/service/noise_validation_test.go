package service

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	discover "github.com/Method-Security/networkscan/generated/go/discover"
	plugins "github.com/Method-Security/networkscan/internal/discover/service/plugins"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func noiseTCP(t *testing.T, serve func(net.Conn)) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var workers sync.WaitGroup
		defer workers.Wait()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				serve(c)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("fixture cleanup timeout")
		}
	})
	return l.Addr().(*net.TCPAddr).Port
}

func noiseUDP(t *testing.T, response func([]byte) []byte) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			n, a, e := c.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = c.WriteTo(response(b[:n]), a)
		}
	}()
	t.Cleanup(func() { _ = c.Close(); <-done })
	return c.LocalAddr().(*net.UDPAddr).Port
}

func noiseCheck(t *testing.T, p Fingerprinter, port int, allowedHTTP bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	result, err := runFingerprinterAttempt(ctx, 1, func(ctx context.Context) (*discover.ServiceDetails, error) {
		return p.Detect(ctx, net.ParseIP("127.0.0.1"), port, "negative.test", 1)
	})
	if result != nil && !(allowedHTTP && result.Protocol == "HTTP") {
		t.Errorf("UNEXPECTED_DETECTION plugin=%T protocol=%s error=%v", p, result.Protocol, err)
	}
}

func TestRegistryNoiseControls(t *testing.T) {
	fixtures := []struct {
		name    string
		payload []byte
		http    bool
	}{
		{"unrelated-text", []byte("unrelated service response\r\n"), false},
		{"http404", []byte("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), true},
		{"unrelated-binary", []byte{0xde, 0xad, 0xbe, 0xef, 0x13, 0x37, 0x42, 0x99, 0x55, 0xaa, 0x66, 0x77, 0x88, 0x99, 0xab, 0xcd}, false},
	}
	for i, p := range tcpPlugins() {
		for _, f := range fixtures {
			t.Run(fmt.Sprintf("tcp/%03d-%s/%s", i, p.Name(), f.name), func(t *testing.T) {
				t.Parallel()
				port := noiseTCP(t, func(c net.Conn) { _, _ = c.Write(f.payload) })
				noiseCheck(t, p, port, f.http)
			})
		}
	}
	for port, p := range udpPlugins() {
		for _, f := range fixtures {
			t.Run(fmt.Sprintf("udp/%d-%s/%s", port, p.Name(), f.name), func(t *testing.T) {
				t.Parallel()
				port := noiseUDP(t, func([]byte) []byte { return f.payload })
				noiseCheck(t, p, port, false)
			})
		}
	}
}

func TestProtocolImpostors(t *testing.T) {
	for i := 0; i < 10; i++ {
		t.Run(fmt.Sprintf("ssh-invalid-identification/%02d", i), func(t *testing.T) {
			t.Parallel()
			port := noiseTCP(t, func(c net.Conn) {
				_, _ = bufio.NewReader(c).ReadString('\n')
				_, _ = fmt.Fprintf(c, "SSH-not-a-version-%d\r\n", i)
			})
			noiseCheck(t, plugins.SSHFingerprinter{}, port, false)
		})
		t.Run(fmt.Sprintf("smtp-against-ftp/%02d", i), func(t *testing.T) {
			t.Parallel()
			port := noiseTCP(t, func(c net.Conn) {
				_, _ = io.WriteString(c, "220 FTP fixture ready\r\n")
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					switch line {
					case "SYST\r\n":
						_, _ = io.WriteString(c, "215 UNIX Type: L8\r\n")
					case "FEAT\r\n":
						_, _ = io.WriteString(c, "211 No extensions\r\n")
					case "QUIT\r\n":
						return
					default:
						_, _ = io.WriteString(c, "500 Unknown FTP command\r\n")
					}
				}
			})
			noiseCheck(t, plugins.SMTPFingerprinter{}, port, false)
		})
		t.Run(fmt.Sprintf("redis-invalid-error-token/%02d", i), func(t *testing.T) {
			t.Parallel()
			port := noiseTCP(t, func(c net.Conn) {
				var b [128]byte
				_, _ = c.Read(b[:])
				_, _ = fmt.Fprintf(c, "-NOAUTHNOTREDIS%d unrelated service\r\n", i)
			})
			noiseCheck(t, plugins.RedisFingerprinter{}, port, false)
		})
		t.Run(fmt.Sprintf("ntp-invalid-version-stratum/%02d", i), func(t *testing.T) {
			t.Parallel()
			port := noiseUDP(t, func([]byte) []byte { b := make([]byte, 48); b[0] = 4; b[1] = byte(200 + i); return b })
			noiseCheck(t, plugins.NTPFingerprinter{}, port, false)
		})
		t.Run(fmt.Sprintf("grpc-ordinary-http2-404/%02d", i), func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(404)
				_, _ = io.WriteString(w, "not a gRPC service")
			}), &http2.Server{}))
			defer server.Close()
			noiseCheck(t, plugins.GrpcFingerprinter{}, server.Listener.Addr().(*net.TCPAddr).Port, false)
		})
	}
}
