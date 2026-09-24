package helpers

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestUpgradeTLSUsesOriginalHostname(t *testing.T) {
	serverName := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		serverName <- hello.ServerName
		return nil, nil
	}}
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := TCPConn(ctx, net.ParseIP("127.0.0.1"), server.Listener.Addr().(*net.TCPAddr).Port, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	secure, err := UpgradeTLS(ctx, conn, "service.test")
	if err != nil {
		t.Fatal(err)
	}
	if !secure.(*tls.Conn).ConnectionState().HandshakeComplete {
		t.Fatal("handshake incomplete")
	}
	select {
	case name := <-serverName:
		if name != "service.test" {
			t.Fatalf("SNI = %q", name)
		}
	case <-ctx.Done():
		t.Fatal("server did not receive TLS hello")
	}
}

func TestUpgradeTLSHonorsCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close(); _ = server.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := UpgradeTLS(ctx, client, "service.test"); err == nil {
		t.Fatal("expected canceled handshake")
	}
	if time.Since(start) > time.Second {
		t.Fatal("TLS handshake ignored context")
	}
}
