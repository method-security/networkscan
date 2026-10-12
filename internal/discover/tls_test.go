package discover

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseJA4SUsesServerExtensionOrderAndIncludesGREASEAndALPN(t *testing.T) {
	extensions := []byte{
		0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, // supported_versions: TLS 1.3
		0x0a, 0x0a, 0x00, 0x00, // GREASE
		0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2', // ALPN: h2
		0x00, 0x33, 0x00, 0x00, // key_share (body omitted for parser fixture)
	}
	serverHello := []byte{0x03, 0x03}
	serverHello = append(serverHello, make([]byte, 32)...)
	serverHello = append(serverHello, 0x00, 0x13, 0x01, 0x00)
	serverHello = binary.BigEndian.AppendUint16(serverHello, uint16(len(extensions)))
	serverHello = append(serverHello, extensions...)

	handshake := []byte{0x02, 0x00, 0x00, 0x00}
	handshake[1] = byte(len(serverHello) >> 16)
	handshake[2] = byte(len(serverHello) >> 8)
	handshake[3] = byte(len(serverHello))
	handshake = append(handshake, serverHello...)

	record := []byte{0x16, 0x03, 0x03, 0x00, 0x00}
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	record = append(record, handshake...)

	const expected = "t1304h2_1301_585237a86ad6"
	if got := parseJA4SFromServerHello(record); got != expected {
		t.Fatalf("expected reference JA4S %q, got %q", expected, got)
	}
}

func TestComputeJA4SReturnsFingerprintForTLS13Server(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	target := strings.TrimPrefix(server.URL, "https://")
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split test server address: %v", err)
	}

	fingerprint := computeJA4S(context.Background(), target, host, 5*time.Second)
	if fingerprint == "" {
		t.Fatal("expected a JA4S fingerprint, got an empty result")
	}
	if !strings.HasPrefix(fingerprint, "t13") {
		t.Fatalf("expected a TLS 1.3 JA4S fingerprint, got %q", fingerprint)
	}
	if len(fingerprint) != 25 {
		t.Fatalf("expected a 25-character JA4S fingerprint, got %q", fingerprint)
	}
}
