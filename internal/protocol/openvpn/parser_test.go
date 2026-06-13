package openvpn

import (
	"encoding/binary"
	"testing"
)

// TestBuildHardResetClientV2 verifies the structure of the 13-byte
// HARD_RESET_CLIENT_V2 control packet.
func TestBuildHardResetClientV2(t *testing.T) {
	pkt, err := BuildHardResetClientV2()
	if err != nil {
		t.Fatalf("BuildHardResetClientV2 returned error: %v", err)
	}
	if len(pkt) != HardResetClientV2Size {
		t.Fatalf("expected %d-byte packet, got %d bytes", HardResetClientV2Size, len(pkt))
	}
	// Verify opcode byte: top 5 bits should be PControlHardResetClientV2 (7)
	opcode := pkt[0] >> POpcodeShift
	if opcode != PControlHardResetClientV2 {
		t.Errorf("expected opcode %d, got %d", PControlHardResetClientV2, opcode)
	}
	// Key ID (bottom 3 bits) should be 0
	keyID := pkt[0] & 0x07
	if keyID != 0 {
		t.Errorf("expected key_id 0, got %d", keyID)
	}
	// Session ID bytes (1-8) should be non-zero with high probability (random)
	allZero := true
	for _, b := range pkt[1 : 1+SessionIDLength] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("session ID appears to be all-zero (random generation may have failed)")
	}
	// ACK array length byte should be 0
	if pkt[9] != 0 {
		t.Errorf("expected ack-array length 0, got %d", pkt[9])
	}
}

// TestBuildTCPHardResetClientV2 verifies the TCP-framed packet has the correct
// length prefix (2 bytes big-endian) and the underlying UDP packet is intact.
func TestBuildTCPHardResetClientV2(t *testing.T) {
	pkt, err := BuildTCPHardResetClientV2()
	if err != nil {
		t.Fatalf("BuildTCPHardResetClientV2 returned error: %v", err)
	}
	// 2-byte length prefix + 14-byte UDP payload = 16 bytes total
	expectedTCPLen := 2 + HardResetClientV2Size
	if len(pkt) != expectedTCPLen {
		t.Fatalf("expected %d-byte TCP-framed packet, got %d bytes", expectedTCPLen, len(pkt))
	}
	payloadLen := binary.BigEndian.Uint16(pkt[0:2])
	if int(payloadLen) != HardResetClientV2Size {
		t.Errorf("expected length prefix %d, got %d", HardResetClientV2Size, payloadLen)
	}
	// The opcode byte in the payload should match HARD_RESET_CLIENT_V2
	opcode := pkt[2] >> POpcodeShift
	if opcode != PControlHardResetClientV2 {
		t.Errorf("expected opcode %d in TCP payload, got %d", PControlHardResetClientV2, opcode)
	}
}

// TestParseControlPacket verifies that ParseControlPacket can parse a synthetic
// HARD_RESET_SERVER_V2 packet.
func TestParseControlPacket(t *testing.T) {
	// Construct a minimal HARD_RESET_SERVER_V2 packet (14 bytes)
	raw := make([]byte, HardResetClientV2Size)
	raw[0] = PControlHardResetServerV2 << POpcodeShift // opcode
	// Bytes 1-8: server session ID (fixed for test)
	for i := 1; i <= 8; i++ {
		raw[i] = byte(i)
	}
	raw[9] = 0x00 // ack-array length
	binary.BigEndian.PutUint32(raw[10:14], 0)

	pkt, err := ParseControlPacket(raw)
	if err != nil {
		t.Fatalf("ParseControlPacket returned error: %v", err)
	}
	if !IsHardResetServer(pkt) {
		t.Errorf("expected HARD_RESET_SERVER_V2 opcode, got %d", pkt.Opcode)
	}
}

// TestParseControlPacketTooShort ensures ParseControlPacket rejects short buffers.
func TestParseControlPacketTooShort(t *testing.T) {
	_, err := ParseControlPacket([]byte{0x40, 0x00})
	if err == nil {
		t.Error("expected error for short packet, got nil")
	}
}

// TestContainsSessionID verifies the session-ID search used to confirm the server
// echoed back our client session ID.
func TestContainsSessionID(t *testing.T) {
	var id [SessionIDLength]byte
	for i := range id {
		id[i] = byte(i + 1)
	}
	// Response that embeds the ID somewhere in the middle
	response := make([]byte, 20)
	copy(response[5:], id[:])
	if !ContainsSessionID(response, id) {
		t.Error("ContainsSessionID returned false for response that contains the session ID")
	}
	// Response that does NOT contain the ID
	blank := make([]byte, 20)
	if ContainsSessionID(blank, id) {
		t.Error("ContainsSessionID returned true for response that does NOT contain the session ID")
	}
}
