package plugins

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	commonprotocol "github.com/Method-Security/networkscan/generated/go/common/protocol"
)

func TestMongoDBNativeHTTPWarningDetectedWithReservedFallbackBudget(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				var prefix [3]byte
				if _, err := io.ReadFull(c, prefix[:]); err != nil || string(prefix[:]) != "GET" {
					return
				}
				nativeTCPDiscoveryExpect(t, c, " / HTTP/1.0\r\n\r\n")
				nativeTCPDiscoverySend(t, c, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nIt looks like you are trying to access MongoDB over HTTP on the native driver port.\r\n")
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("fixture did not stop")
		}
	})

	result, err := (MongoDBFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), listener.Addr().(*net.TCPAddr).Port, "localhost", 2)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Protocol != common.ProtocolTypeMongodb || result.Version == nil || *result.Version != "MongoDB 3.6 after 3.6.3, or 3.7.3 or later" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestFingerResponseRequiresPortScopedLoginEvidence(t *testing.T) {
	for _, tc := range []struct {
		name  string
		text  string
		port  int
		match bool
	}{
		{"ftp-banner", "220 Welcome to www.net.cn.\r\n530 Please login with USER and PASS.\r\n", 21, false},
		{"telnet-login", "login: ", 23, false},
		{"finger-login", "Login: root\n", 79, true},
		{"finger-explicit", "No information.\n", 7079, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isFingerResponse(tc.text, tc.port); got != tc.match {
				t.Fatalf("match=%v want=%v", got, tc.match)
			}
		})
	}
}

func TestFTPLoginRequiredRepliesStillDetect(t *testing.T) {
	port := nativeTCPDiscoveryListener(t, func(c net.Conn) {
		nativeTCPDiscoverySend(t, c, "220 Welcome to www.net.cn.\r\n")
		nativeTCPDiscoveryExpect(t, c, "SYST\r\n")
		nativeTCPDiscoverySend(t, c, "530 Please login with USER and PASS.\r\n")
		nativeTCPDiscoveryExpect(t, c, "FEAT\r\n")
		nativeTCPDiscoverySend(t, c, "530 Please login with USER and PASS.\r\n")
	})

	result, err := (FTPFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Protocol != common.ProtocolTypeFtp || result.Metadata.Generic.Metadata["authRequired"] != "true" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestFTPMisconfigurationBannerStillDetects(t *testing.T) {
	port := nativeTCPDiscoveryListener(t, func(c net.Conn) {
		nativeTCPDiscoverySend(t, c, "500 OOPS: tcp_wrappers is set to YES but no tcp wrapper support compiled in\r\n")
	})

	result, err := (FTPFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Protocol != common.ProtocolTypeFtp || result.Metadata.Generic.Metadata["misconfigured"] != "true" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestElasticsearchSecurityExceptionDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.Header().Set("WWW-Authenticate", `Basic realm="security" charset="UTF-8"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"root_cause":[{"type":"security_exception","reason":"missing authentication credentials"}],"type":"security_exception","reason":"missing authentication credentials"},"status":401}`)
	}))
	defer server.Close()

	result, err := (ElasticsearchFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, server.Listener.Addr()), "product.test", 2)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Protocol != common.ProtocolTypeElasticsearch || result.Metadata.Generic.Metadata["authRequired"] != "true" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestHTTPFrontingErrorsRejected(t *testing.T) {
	for _, body := range []string{
		"Client sent an HTTP request to an HTTPS server.",
		"The request hostname is invalid.",
	} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()

			result, err := (HTTPDiscoveryFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, server.Listener.Addr()), "product.test", 2)
			if err != nil {
				t.Fatal(err)
			}
			if result != nil {
				t.Fatalf("fronting error matched HTTP: %#v", result)
			}
		})
	}
}

func TestSMBV1OnlyErrorBuildsDetection(t *testing.T) {
	err := fmt.Errorf("failed to connect: target 127.0.0.1:445 is only accepting SMBv1, but SMBv1 support is not implemented")
	if !isSMBv1OnlyError(err) {
		t.Fatal("SMBv1-only error was not recognized")
	}
	result := buildSMBv1OnlyResult("localhost", net.ParseIP("127.0.0.1"), 445)
	if result.Protocol != common.ProtocolTypeSmb || result.Metadata == nil || result.Metadata.Smb == nil || result.Metadata.Smb.SmbVersion == nil || *result.Metadata.Smb.SmbVersion != commonprotocol.SmbVersionSmb1 {
		t.Fatalf("unexpected result: %#v", result)
	}
}
