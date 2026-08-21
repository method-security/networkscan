package plugins

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// serveOnce accepts one connection, reads the greeting and writes reply, then closes.
func serveOnce(t *testing.T, reply []byte) (net.IP, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 8)
		_, _ = conn.Read(buf)
		if len(reply) > 0 {
			_, _ = conn.Write(reply)
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.IP, addr.Port
}

func TestSOCKSDetectAuthMethods(t *testing.T) {
	cases := []struct {
		name   string
		reply  []byte
		method string
	}{
		{"no auth", []byte{0x05, 0x00}, "NO_AUTH"},
		{"gssapi", []byte{0x05, 0x01}, "GSSAPI"},
		{"username password", []byte{0x05, 0x02}, "USERNAME_PASSWORD"},
		{"no acceptable", []byte{0x05, 0xff}, "NO_ACCEPTABLE_METHODS"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip, port := serveOnce(t, tc.reply)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			details, err := SOCKSFingerprinter{}.Detect(ctx, ip, port, "127.0.0.1", 2)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if details.Port != port {
				t.Errorf("port = %d, want %d", details.Port, port)
			}
			if details.Metadata == nil || details.Metadata.Generic == nil {
				t.Fatalf("missing generic metadata")
			}
			if got := details.Metadata.Generic.Metadata["auth_method"]; got != tc.method {
				t.Errorf("auth_method = %q, want %q", got, tc.method)
			}
		})
	}
}

func TestSOCKSDetectRejectsNonSocks(t *testing.T) {
	cases := []struct {
		name  string
		reply []byte
	}{
		{"http banner", []byte("HTTP/1.1 400 Bad Request\r\n")},
		{"wrong version", []byte{0x04, 0x00}},
		{"unknown method", []byte{0x05, 0x7a}},
		{"short reply", []byte{0x05}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip, port := serveOnce(t, tc.reply)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			fingerprinter := SOCKSFingerprinter{}
			if _, err := fingerprinter.Detect(ctx, ip, port, "127.0.0.1", 2); err == nil {
				t.Errorf("Detect(%s) succeeded, want error", strconv.Quote(tc.name))
			}
		})
	}
}
