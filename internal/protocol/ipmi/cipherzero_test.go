package ipmi

import (
	"encoding/binary"
	"testing"
)

func TestBuildCipherZeroOpenSessionRequest(t *testing.T) {
	req := BuildCipherZeroOpenSessionRequest(0x55, 0xA1A2A3A4)
	if got, want := len(req), RMCPHeaderSize+IPMI20SessionHeaderSize+OpenSessionPayloadSize; got != want {
		t.Fatalf("len(req)=%d, want %d", got, want)
	}
	// Validate RMCP + RMCP+ envelope.
	if req[0] != RMCPVersion || req[3] != RMCPClassIPMI {
		t.Fatalf("bad RMCP envelope: % x", req[:4])
	}
	if req[4] != AuthTypeRMCPPlus {
		t.Fatalf("session auth type = 0x%02x, want 0x06", req[4])
	}
	if req[5] != PayloadTypeOpenSessionRequest {
		t.Fatalf("session payload type = 0x%02x, want 0x10", req[5])
	}
	payload := req[RMCPHeaderSize+IPMI20SessionHeaderSize:]

	// All three cipher-suite algorithms must be NONE (CVE-2013-4031).
	if payload[12] != AuthAlgorithmRAKPNone {
		t.Fatalf("auth alg = 0x%02x, want 0x00", payload[12])
	}
	if payload[20] != IntegrityAlgorithmNone {
		t.Fatalf("integrity alg = 0x%02x, want 0x00", payload[20])
	}
	if payload[28] != ConfidentialityAlgorithmNone {
		t.Fatalf("confidentiality alg = 0x%02x, want 0x00", payload[28])
	}

	// Message tag and console session ID echo through.
	if payload[0] != 0x55 {
		t.Fatalf("message tag = 0x%02x, want 0x55", payload[0])
	}
	if got := binary.LittleEndian.Uint32(payload[4:8]); got != 0xA1A2A3A4 {
		t.Fatalf("console session id = 0x%08x, want 0xA1A2A3A4", got)
	}
}

// buildOpenSessionResponse synthesizes a full Open Session Response
// (36-byte payload) with the supplied status and managed-system
// session ID.
func buildOpenSessionResponse(t *testing.T, status byte, bmcSID uint32) []byte {
	t.Helper()
	payload := make([]byte, 36)
	payload[0] = 0x55   // tag echo
	payload[1] = status // status code
	payload[2] = 0x04   // privilege granted
	binary.LittleEndian.PutUint32(payload[4:8], 0xA1A2A3A4)
	binary.LittleEndian.PutUint32(payload[8:12], bmcSID)
	// Three nested-payload echoes — we only validate the alg ID bytes.
	payload[12], payload[16], payload[20] = 0x00, 0x00, 0x01
	payload[24], payload[28], payload[32] = 0x00, 0x00, 0x02
	rmcp := BuildRMCPHeader()
	sess := BuildIPMI20SessionHeader(PayloadTypeOpenSessionResponse, 0, 0, uint16(len(payload)))
	out := append(append(append([]byte{}, rmcp...), sess...), payload...)
	return out
}

func TestParseOpenSessionResponseAccepted(t *testing.T) {
	resp := buildOpenSessionResponse(t, RMCPPlusStatusNoErrors, 0xDEADBEEF)
	parsed, err := ParseOpenSessionResponse(resp)
	if err != nil {
		t.Fatalf("ParseOpenSessionResponse() err = %v", err)
	}
	if !parsed.Accepted() {
		t.Fatalf("expected Accepted()=true")
	}
	if parsed.BMCSessionID != 0xDEADBEEF {
		t.Fatalf("BMCSessionID = 0x%08x, want 0xDEADBEEF", parsed.BMCSessionID)
	}
	if parsed.ConsoleSessionID != 0xA1A2A3A4 {
		t.Fatalf("ConsoleSessionID = 0x%08x, want 0xA1A2A3A4", parsed.ConsoleSessionID)
	}
}

func TestParseOpenSessionResponseRejected(t *testing.T) {
	resp := buildOpenSessionResponse(t, RMCPPlusStatusInvalidAuthAlgorithm, 0)
	parsed, err := ParseOpenSessionResponse(resp)
	if err != nil {
		t.Fatalf("ParseOpenSessionResponse() err = %v", err)
	}
	if parsed.Accepted() {
		t.Fatalf("expected Accepted()=false for status 0x%02x", parsed.StatusCode)
	}
}
