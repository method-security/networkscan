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
// (36-byte payload) with the supplied status, managed-system session
// ID, and negotiated algorithms (auth at payload[16], integrity at
// payload[24], confidentiality at payload[32]). Cipher Zero requires
// all three to be 0x00 (NONE).
func buildOpenSessionResponse(t *testing.T, status byte, bmcSID uint32, authAlg, integrityAlg, confAlg byte) []byte {
	t.Helper()
	payload := make([]byte, 36)
	payload[0] = 0x55   // tag echo
	payload[1] = status // status code
	payload[2] = 0x04   // privilege granted
	binary.LittleEndian.PutUint32(payload[4:8], 0xA1A2A3A4)
	binary.LittleEndian.PutUint32(payload[8:12], bmcSID)
	// Three nested-payload echoes (type byte + reserved + length + alg byte).
	payload[12] = openSessionPayloadTypeAuthentication
	payload[16] = authAlg
	payload[20] = openSessionPayloadTypeIntegrity
	payload[24] = integrityAlg
	payload[28] = openSessionPayloadTypeConfidentiality
	payload[32] = confAlg
	rmcp := BuildRMCPHeader()
	sess := BuildIPMI20SessionHeader(PayloadTypeOpenSessionResponse, 0, 0, uint16(len(payload)))
	out := append(append(append([]byte{}, rmcp...), sess...), payload...)
	return out
}

func TestParseOpenSessionResponseAccepted(t *testing.T) {
	// All three algorithms negotiated as NONE — the real Cipher Zero accept path.
	resp := buildOpenSessionResponse(t, RMCPPlusStatusNoErrors, 0xDEADBEEF,
		AuthAlgorithmRAKPNone, IntegrityAlgorithmNone, ConfidentialityAlgorithmNone)
	parsed, err := ParseOpenSessionResponse(resp)
	if err != nil {
		t.Fatalf("ParseOpenSessionResponse() err = %v", err)
	}
	if !parsed.Accepted() {
		t.Fatalf("expected Accepted()=true")
	}
	if !parsed.IsCipherZeroAccepted() {
		t.Fatalf("expected IsCipherZeroAccepted()=true when all algs are NONE")
	}
	if parsed.BMCSessionID != 0xDEADBEEF {
		t.Fatalf("BMCSessionID = 0x%08x, want 0xDEADBEEF", parsed.BMCSessionID)
	}
	if parsed.ConsoleSessionID != 0xA1A2A3A4 {
		t.Fatalf("ConsoleSessionID = 0x%08x, want 0xA1A2A3A4", parsed.ConsoleSessionID)
	}
}

// TestIsCipherZeroAcceptedStatusOKButAlgsNotNone covers the false-positive
// scenario: a BMC returns status = 0 but quietly substitutes HMAC-SHA1 / AES-CBC
// for the requested NONE suite. The Cipher-Zero predicate must NOT report a
// finding, but Accepted() should still return true (the session itself opened),
// so the RAKP existence-oracle path keeps working.
func TestIsCipherZeroAcceptedStatusOKButAlgsNotNone(t *testing.T) {
	resp := buildOpenSessionResponse(t, RMCPPlusStatusNoErrors, 0xDEADBEEF,
		AuthAlgorithmRAKPHMACSHA1, IntegrityAlgorithmHMACSHA196, ConfidentialityAlgorithmAESCBC128)
	parsed, err := ParseOpenSessionResponse(resp)
	if err != nil {
		t.Fatalf("ParseOpenSessionResponse() err = %v", err)
	}
	if !parsed.Accepted() {
		t.Fatalf("expected Accepted()=true on status-OK session-open (RAKP oracle depends on this)")
	}
	if parsed.IsCipherZeroAccepted() {
		t.Fatalf("expected IsCipherZeroAccepted()=false: status was OK but negotiated algs were not NONE (auth=0x%02x integrity=0x%02x conf=0x%02x)",
			parsed.NegotiatedAuthAlg, parsed.NegotiatedIntegrityAlg, parsed.NegotiatedConfAlg)
	}
}

func TestParseOpenSessionResponseRejected(t *testing.T) {
	resp := buildOpenSessionResponse(t, RMCPPlusStatusInvalidAuthAlgorithm, 0,
		AuthAlgorithmRAKPNone, IntegrityAlgorithmNone, ConfidentialityAlgorithmNone)
	parsed, err := ParseOpenSessionResponse(resp)
	if err != nil {
		t.Fatalf("ParseOpenSessionResponse() err = %v", err)
	}
	if parsed.Accepted() {
		t.Fatalf("expected Accepted()=false for status 0x%02x", parsed.StatusCode)
	}
}
