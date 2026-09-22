package helpers

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
)

func TestConnectServiceTLSAndSNI(t *testing.T) {
	sni := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		sni <- hello.ServerName
		return nil, nil
	}}
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	port := server.Listener.Addr().(*net.TCPAddr).Port
	conn, endpoint, err := ConnectService(ctx, net.ParseIP("127.0.0.1"), port, "service.test", 2, common.TransportTypeTcptls)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if endpoint.Host != "service.test" || endpoint.Address.Port() != uint16(port) || endpoint.Context != ctx {
		t.Fatalf("incorrect endpoint: %+v", endpoint)
	}
	if _, ok := conn.(*tls.Conn); !ok {
		t.Fatalf("expected TLS connection, got %T", conn)
	}
	select {
	case name := <-sni:
		if name != "service.test" {
			t.Fatalf("SNI = %q", name)
		}
	case <-ctx.Done():
		t.Fatal("TLS handshake did not supply SNI")
	}
}

func TestConnectServiceUDP(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := ConnectService(ctx, net.ParseIP("127.0.0.1"), server.LocalAddr().(*net.UDPAddr).Port, "udp.test", 2, common.TransportTypeUdp)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("test")); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 8)
	n, _, err := server.ReadFrom(b)
	if err != nil || string(b[:n]) != "test" {
		t.Fatalf("UDP receive = %q, %v", b[:n], err)
	}
}

func TestConnectServiceCancellationClosesTCP(t *testing.T) {
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, _, err := ConnectService(ctx, net.ParseIP("127.0.0.1"), server.Addr().(*net.TCPAddr).Port, "tcp.test", -1, common.TransportTypeTcp)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	peer, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	cancel()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("cancellation did not close connection: %v", err)
	}
}

func TestConnectServiceRejectsInvalidEndpoint(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		if _, _, err := ConnectService(context.Background(), net.ParseIP("127.0.0.1"), port, "service.test", 1, common.TransportTypeTcp); err == nil {
			t.Fatalf("accepted port %d", port)
		}
	}
	if _, _, err := ConnectService(context.Background(), nil, 80, "service.test", 1, common.TransportTypeTcp); err == nil {
		t.Fatal("accepted nil IP")
	}
}
