package plugins

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
)

func identificationRegressionListener(t *testing.T, secure bool, serve func(net.Conn)) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if secure {
		listener = tls.NewListener(listener, nativeTCPDiscoveryTLS(t))
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			serve(conn)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("identification fixture did not stop")
		}
	})
	return listener.Addr().(*net.TCPAddr).Port
}

func TestSSHIdentificationRegression(t *testing.T) {
	for _, tc := range []struct {
		name, response, version string
	}{
		{"modern", "SSH-2.0-OpenSSH_9.8 local comment\r\n", "SSH-2.0-OpenSSH_9.8 local comment"},
		{"hyphenated-software", "SSH-2.0-Vendor-SSH_1.0 local comment\r\n", "SSH-2.0-Vendor-SSH_1.0 local comment"},
		{"preamble", "Authorized access only\r\nWelcome\nSSH-2.0-LocalSSH_1.0\r\n", "SSH-2.0-LocalSSH_1.0"},
		{"compatibility", "SSH-1.99-LocalSSH_1.0\r\n", "SSH-1.99-LocalSSH_1.0"},
		{"legacy", "SSH-1.5-LocalSSH_1.0\n", "SSH-1.5-LocalSSH_1.0"},
		{"invalid-version", "SSH-not-a-version\r\n", ""},
		{"prefix-only", "SSH unrelated service\r\n", ""},
		{"missing-software", "SSH-2.0-\r\n", ""},
		{"invalid-software", "SSH-2.0-local\x00server\r\n", ""},
		{"truncated", "SSH-2.0-LocalSSH_1.0", ""},
		{"oversized-identification", "SSH-2.0-" + strings.Repeat("x", 246) + "\r\n", ""},
		{"oversized-preamble", strings.Repeat("x", 8192) + "\nSSH-2.0-LocalSSH\r\n", ""},
		{"too-many-preamble-lines", strings.Repeat("notice\r\n", 64) + "SSH-2.0-LocalSSH\r\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := identificationRegressionListener(t, false, func(c net.Conn) {
				nativeTCPDiscoveryExpect(t, c, "SSH-2.0-GoSSHScanner\r\n")
				for start := 0; start < len(tc.response); start += 3 {
					if _, err := io.WriteString(c, tc.response[start:min(start+3, len(tc.response))]); err != nil {
						return
					}
				}
			})
			result, err := (SSHFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 1)
			if tc.version == "" {
				if result != nil || err == nil {
					t.Fatalf("accepted invalid identification: %#v, %v", result, err)
				}
				return
			}
			if err != nil || result == nil {
				t.Fatalf("lost SSH identification: %v", err)
			}
			if result.Protocol != common.ProtocolTypeSsh || result.Version == nil || *result.Version != tc.version ||
				result.Metadata.Ssh == nil || *result.Metadata.Ssh.ServerVersion != tc.version ||
				*result.Metadata.Ssh.Target != fmt.Sprintf("localhost:%d", port) {
				t.Fatalf("lost SSH metadata: %#v", result)
			}
		})
	}
}

func TestSMTPIdentificationRegression(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, tc := range []struct {
			name, greeting, ehlo, helo string
			valid, extensions          bool
		}{
			{"extensions", "220-local ESMTP\r\n220 Ready\r\n", "250-local\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 1024\r\n", "", true, true},
			{"helo-fallback", "220 local SMTP\r\n", "500 EHLO unknown\r\n", "250 local\r\n", true, false},
			{"helo-502", "220 local SMTP\r\n", "502 Unsupported\r\n", "250 local\r\n", true, false},
			{"helo-504", "220 local SMTP\r\n", "504 Unsupported\r\n", "250 local\r\n", true, false},
			{"bare-code", "220\r\n", "250\r\n", "", true, false},
			{"ftp", "220 FTP fixture ready\r\n", "500 Unknown FTP command\r\n", "500 Unknown FTP command\r\n", false, false},
			{"banner-only", "220 local ESMTP\r\n", "", "", false, false},
			{"bad-greeting-boundary", "220NOTSMTP\r\n", "", "", false, false},
			{"bad-reply-boundary", "220 local\r\n", "250NOTSMTP\r\n", "", false, false},
			{"wrong-continuation", "220 local\r\n", "250-local\r\n550 denied\r\n", "", false, false},
			{"truncated-continuation", "220 local\r\n", "250-local\r\n250-STARTTLS\r\n", "", false, false},
			{"oversized-reply", "220 local\r\n", "250 " + strings.Repeat("x", 8192) + "\r\n", "", false, false},
		} {
			t.Run(fmt.Sprintf("tls=%t/%s", secure, tc.name), func(t *testing.T) {
				port := identificationRegressionListener(t, secure, func(c net.Conn) {
					_, _ = io.WriteString(c, tc.greeting)
					if tc.ehlo == "" {
						return
					}
					nativeTCPDiscoveryExpect(t, c, "EHLO scanner.local\r\n")
					_, _ = io.WriteString(c, tc.ehlo)
					if tc.helo != "" {
						nativeTCPDiscoveryExpect(t, c, "HELO scanner.local\r\n")
						_, _ = io.WriteString(c, tc.helo)
					}
				})
				var probe nativeTCPDiscoveryProbe = SMTPFingerprinter{}
				wantProtocol := common.ProtocolTypeSmtp
				if secure {
					probe = SMTPTLSFingerprinter{}
					wantProtocol = common.ProtocolTypeSmtps
				}
				result, err := probe.Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 1)
				if !tc.valid {
					if result != nil || err == nil {
						t.Fatalf("accepted non-SMTP reply: %#v, %v", result, err)
					}
					return
				}
				if err != nil || result == nil || result.Protocol != wantProtocol {
					t.Fatalf("lost SMTP service: %#v, %v", result, err)
				}
				if secure {
					if result.Tls == nil || !*result.Tls || (tc.extensions && result.Metadata.Generic.Metadata["authMethods"] != "[PLAIN LOGIN]") {
						t.Fatalf("lost SMTPS metadata: %#v", result)
					}
				} else if tc.extensions {
					meta := result.Metadata.Smtp
					if !*meta.EsmtpSupported || !*meta.TlsSupported || len(meta.AuthMethods) != 2 || len(meta.SupportedExtensions) != 3 || *meta.Banner != "220-local ESMTP" {
						t.Fatalf("lost SMTP capabilities: %#v", meta)
					}
				} else if tc.helo != "" && *result.Metadata.Smtp.EsmtpSupported {
					t.Fatal("HELO fallback reported ESMTP support")
				}
			})
		}
	}
}

func TestRedisIdentificationRegression(t *testing.T) {
	info := "# Server\r\nredis_version:7.4.1\r\nredis_mode:standalone\r\n"
	for _, secure := range []bool{false, true} {
		for _, tc := range []struct{ name, response, state string }{
			{"pong", "+PONG\r\n", "pong"},
			{"auth", "-NOAUTH Authentication required.\r\n", "auth_required"},
			{"bare-auth", "-NOAUTH\r\n", "auth_required"},
			{"protected", "-DENIED Redis is running in protected mode.\r\n", "protected_mode"},
			{"info", fmt.Sprintf("$%d\r\n%s\r\n", len(info), info), "info"},
			{"false-noauth", "-NOAUTHNOTREDIS unrelated service\r\n", ""},
			{"false-denied", "-DENIEDNOTREDIS Redis is running in protected mode\r\n", ""},
			{"false-err", "-ERRNOTREDIS redis\r\n", ""},
			{"false-pong", "+PONGNOTREDIS\r\n", ""},
			{"truncated-auth", "-NOAUTH Authentication required.", ""},
		} {
			t.Run(fmt.Sprintf("tls=%t/%s", secure, tc.name), func(t *testing.T) {
				port := identificationRegressionListener(t, secure, func(c net.Conn) {
					reader := bufio.NewReader(c)
					first, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					lines := 0
					if first == "*1\r\n" {
						lines = 2
					} else if first == "*2\r\n" {
						lines = 4
					}
					for i := 0; i < lines; i++ {
						if _, err := reader.ReadString('\n'); err != nil {
							return
						}
					}
					_, _ = io.WriteString(c, tc.response)
				})
				var probe nativeTCPDiscoveryProbe = RedisFingerprinter{}
				if secure {
					probe = RedisTLSFingerprinter{}
				}
				result, err := probe.Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 1)
				if tc.state == "" {
					if result != nil || err == nil {
						t.Fatalf("accepted non-Redis response: %#v, %v", result, err)
					}
					return
				}
				if err != nil || result == nil || result.Protocol != common.ProtocolTypeRedis || result.Metadata.Generic.Metadata["state"] != tc.state {
					t.Fatalf("lost Redis service: %#v, %v", result, err)
				}
				if secure && (result.Tls == nil || !*result.Tls) {
					t.Fatal("lost Redis TLS flag")
				}
				if tc.state == "info" && (result.Version == nil || *result.Version != "7.4.1" || result.Metadata.Generic.Metadata["redis_mode"] != "standalone") {
					t.Fatalf("lost Redis INFO metadata: %#v", result)
				}
			})
		}
	}
}
