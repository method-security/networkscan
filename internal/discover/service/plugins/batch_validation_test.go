package plugins

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/miekg/dns"
)

// Opt-in because this batch deliberately waits for 200 real socket timeouts.
func TestThousandTargetValidation(t *testing.T) {
	if os.Getenv("NETWORKSCAN_BATCH_VALIDATION") != "1" {
		t.Skip("set NETWORKSCAN_BATCH_VALIDATION=1 to run the 1000-target batch")
	}
	tlsConfig := nativeTCPDiscoveryTLS(t)
	groups := []struct {
		name, protocol string
		count          int
		probe          nativeDatabaseDetector
		udp            bool
	}{
		{"http", "HTTP", 200, HTTPDiscoveryFingerprinter{}, false},
		{"https", "HTTPS", 200, HTTPSFingerprinter{}, false},
		{"ssh", "SSH", 60, SSHFingerprinter{}, false},
		{"ftp", "FTP", 60, FTPFingerprinter{}, false},
		{"smtp", "SMTP", 60, SMTPFingerprinter{}, false},
		{"redis", "REDIS", 60, RedisFingerprinter{}, false},
		{"mysql", "MYSQL", 60, MySQLFingerprinter{}, false},
		{"postgres", "POSTGRESQL", 60, PostgresFingerprinter{}, false},
		{"rdp", "RDP", 60, RDPFingerprinter{}, false},
		{"mqtt", "MQTT3", 60, MQTT3Fingerprinter{}, false},
		{"dns", "DNS", 60, DNSFingerprinter{}, true},
		{"stun", "STUN", 60, STUNFingerprinter{}, true},
	}
	for _, group := range groups {
		for i := 0; i < group.count; i++ {
			mode := "positive"
			if i%5 == 3 {
				mode = "negative"
			}
			if i%5 == 4 {
				mode = "timeout"
			}
			t.Run(fmt.Sprintf("%s/%s/%03d", group.name, mode, i), func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var port int
				if group.udp {
					port = batchUDPFixture(t, ctx, group.name, mode)
				} else {
					port = batchTCPFixture(t, func(c net.Conn) {
						if mode == "timeout" {
							<-ctx.Done()
							return
						}
						if group.name == "https" {
							s := tls.Server(c, tlsConfig.Clone())
							if err := s.Handshake(); err != nil {
								return
							}
							if s.ConnectionState().ServerName != "batch.test" {
								t.Error("incorrect TLS SNI")
							}
							c = s
						}
						if mode == "negative" {
							_, _ = io.WriteString(c, "unrelated service\r\n")
							return
						}
						batchPositiveTCP(t, c, group.name, i)
					})
				}
				budget := 3
				if mode == "timeout" {
					budget = 1
				}
				start := time.Now()
				// Match the attempt context supplied by the discovery runner.
				attemptCtx, stop := context.WithTimeout(ctx, time.Duration(budget)*time.Second)
				defer stop()
				result, err := group.probe.Detect(attemptCtx, net.ParseIP("127.0.0.1"), port, "batch.test", budget)
				elapsed := time.Since(start)
				cancel()
				t.Logf("target=127.0.0.1:%d protocol=%s mode=%s elapsed=%s error=%v", port, group.name, mode, elapsed, err)
				if elapsed > time.Duration(budget)*time.Second+750*time.Millisecond {
					t.Errorf("attempt exceeded %ds budget: %s", budget, elapsed)
				}
				if mode != "positive" {
					if result != nil {
						t.Errorf("false positive: %+v", result)
					}
					return
				}
				if err != nil || result == nil {
					t.Fatalf("missed positive: %v", err)
				}
				if string(result.Protocol) != group.protocol {
					t.Errorf("protocol=%s want=%s", result.Protocol, group.protocol)
				}
				if result.Ip != "127.0.0.1" || result.Port != port || result.Host != "batch.test" {
					t.Errorf("wrong target mapping: %+v", result)
				}
				if group.name == "https" && (result.Tls == nil || !*result.Tls) {
					t.Error("missing TLS flag")
				}
				encoded, err := json.Marshal(result)
				if err != nil {
					t.Fatal(err)
				}
				var decoded discover.ServiceDetails
				if err := json.Unmarshal(encoded, &decoded); err != nil {
					t.Fatal(err)
				}
				if decoded.Protocol != result.Protocol || decoded.Host != result.Host || decoded.Port != port || decoded.Metadata == nil {
					t.Error("service JSON round-trip lost data")
				}
			})
		}
	}
}

func batchTCPFixture(t *testing.T, serve func(net.Conn)) int {
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
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				serve(c)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("fixture failed to stop")
		}
	})
	return l.Addr().(*net.TCPAddr).Port
}

func batchPositiveTCP(t *testing.T, c net.Conn, protocol string, variant int) {
	t.Helper()
	r := bufio.NewReader(c)
	send := func(s string) { _, _ = io.WriteString(c, s) }
	switch protocol {
	case "http", "https":
		req, err := http.ReadRequest(r)
		if err != nil {
			t.Error(err)
			return
		}
		_ = req.Body.Close()
		if !strings.HasPrefix(req.Host, "batch.test") {
			t.Errorf("Host=%s", req.Host)
		}
		status := []int{200, 301, 401, 403, 404, 500}[variant%6]
		body := fmt.Sprintf("<html><title>fixture-%d</title></html>", variant)
		if variant%2 == 0 {
			send(fmt.Sprintf("HTTP/1.1 %d %s\r\nServer: LocalFixture\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(body), body))
		} else {
			send(fmt.Sprintf("HTTP/1.1 %d %s\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", status, http.StatusText(status), len(body), body))
		}
	case "ssh":
		_, _ = r.ReadString('\n')
		send(fmt.Sprintf("SSH-2.0-OpenSSH_9.%d\r\n", variant%10))
	case "ftp":
		send("220 FTP local fixture\r\n")
		_, _ = r.ReadString('\n')
		send("215 UNIX Type: L8\r\n")
		_, _ = r.ReadString('\n')
		send("211-Features\r\n UTF8\r\n211 End\r\n")
	case "smtp":
		send("220 local ESMTP fixture\r\n")
		_, _ = r.ReadString('\n')
		send("250-local\r\n250 SIZE 1024\r\n")
		_, _ = r.ReadString('\n')
	case "redis":
		b := make([]byte, 14)
		_, _ = io.ReadFull(r, b)
		if variant%2 == 0 {
			send("+PONG\r\n")
		} else {
			send("-NOAUTH Authentication required.\r\n")
		}
	case "mysql":
		_, _ = c.Write(nativeDatabaseMySQL())
	case "postgres":
		nativeDatabaseReadProbe(t, c, "postgres")
		_, _ = c.Write(nativeDatabasePG('R', []byte{0, 0, 0, 5, 1, 2, 3, 4}))
	case "rdp":
		var h [4]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return
		}
		_, _ = io.CopyN(io.Discard, r, int64(binary.BigEndian.Uint16(h[2:]))-4)
		_, _ = c.Write([]byte{3, 0, 0, 19, 14, 0xd0, 0, 0, 0, 0, 0, 2, 0, 8, 0, 0, 0, 0, 0})
	case "mqtt":
		var h [2]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return
		}
		_, _ = io.CopyN(io.Discard, r, int64(h[1]))
		_, _ = c.Write([]byte{0x20, 2, 0, 0})
	}
}

func batchUDPFixture(t *testing.T, ctx context.Context, protocol, mode string) int {
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
			n, addr, err := c.ReadFrom(b)
			if err != nil {
				return
			}
			if mode == "timeout" {
				<-ctx.Done()
				return
			}
			reply := []byte("unrelated service")
			if mode == "positive" {
				if protocol == "dns" {
					var q dns.Msg
					if err := q.Unpack(b[:n]); err != nil {
						t.Error(err)
						return
					}
					var response dns.Msg
					response.SetReply(&q)
					reply, err = response.Pack()
					if err != nil {
						t.Error(err)
						return
					}
				} else {
					if n < 20 {
						t.Error("short STUN request")
						return
					}
					reply = append([]byte(nil), b[:20]...)
					binary.BigEndian.PutUint16(reply, 0x0101)
					binary.BigEndian.PutUint16(reply[2:], 0)
				}
			}
			_, _ = c.WriteTo(reply, addr)
		}
	}()
	t.Cleanup(func() { _ = c.Close(); <-done })
	return c.LocalAddr().(*net.UDPAddr).Port
}
