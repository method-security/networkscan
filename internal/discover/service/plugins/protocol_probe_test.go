package plugins

import (
	"testing"

	"github.com/Method-Security/networkscan/generated/go/common"
)

func TestLooksLikePcworxResponse(t *testing.T) {
	resp := []byte{
		0x81, 0x01, 0x00, 0x14,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x00,
		0x00, 0x2e, 0x00, 0x00,
	}
	if !looksLikePcworxResponse(resp) {
		t.Fatal("expected PCWorx response to match")
	}
	resp[13] = 0x03
	if looksLikePcworxResponse(resp) {
		t.Fatal("expected modified PCWorx response to be rejected")
	}
}

func TestPPTPInitialControlMessage(t *testing.T) {
	resp := []byte{
		0x00, 0x10, 0x00, 0x01,
		0x1a, 0x2b, 0x3c, 0x4d,
		0x00, 0x05, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}
	result, err := buildPPTPResultFromResponse("host", []byte{192, 0, 2, 1}, 1723, resp)
	if err != nil {
		t.Fatalf("expected PPTP response to match: %v", err)
	}
	if result.Protocol != common.ProtocolTypePptp {
		t.Fatalf("unexpected protocol: %v", result.Protocol)
	}
}

func TestFOXTextPayload(t *testing.T) {
	text := "fox a 0 -1 fox hello\n{\nfox.version=s:1.0\nid=i:7\napp.name=s:Station\napp.version=s:4.10.2\n};;\n"
	parsed := parseFOXTextPayload(text)
	if parsed["fox.version"] != "1.0" {
		t.Fatalf("unexpected fox.version: %q", parsed["fox.version"])
	}
	if parsed["app.version"] != "4.10.2" {
		t.Fatalf("unexpected app.version: %q", parsed["app.version"])
	}
}

func TestWinboxProbeResponses(t *testing.T) {
	modern := make([]byte, 35)
	modern[0] = 0x21
	modern[1] = 0x06
	modern[34] = 0x01
	if !looksLikeModernWinboxProbeResponse(modern) {
		t.Fatal("expected modern WinBox response to match")
	}

	legacy := make([]byte, 250)
	legacy[0] = 0xf8
	legacy[1] = 0x05
	legacy[12] = 0x01
	if !looksLikeLegacyWinboxProbeResponse(legacy) {
		t.Fatal("expected legacy WinBox response to match")
	}

	zeros := make([]byte, 250)
	zeros[0] = 0xf8
	zeros[1] = 0x05
	if looksLikeLegacyWinboxProbeResponse(zeros) {
		t.Fatal("expected all-zero legacy WinBox response to be rejected")
	}
}

func TestMongoNativeHTTPWarning(t *testing.T) {
	resp := []byte("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 85\r\n\r\nIt looks like you are trying to access MongoDB over HTTP on the native driver port.\r\n")
	version, ok := mongoVersionFromNativeHTTPWarning(resp)
	if !ok {
		t.Fatal("expected MongoDB native-port warning to match")
	}
	if version != "MongoDB 3.6 after 3.6.3, or 3.7.3 or later" {
		t.Fatalf("unexpected version: %q", version)
	}

	if _, ok := mongoVersionFromNativeHTTPWarning([]byte("HTTP/1.0 200 OK\r\n\r\nhello")); ok {
		t.Fatal("expected generic HTTP response to be rejected")
	}
}
