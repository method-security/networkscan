package wireguard

import (
	"testing"
)

// TestBuildHandshakeInitiation verifies the 148-byte packet structure:
// correct type byte, length, and reserved bytes.
func TestBuildHandshakeInitiation(t *testing.T) {
	pkt, err := BuildHandshakeInitiation()
	if err != nil {
		t.Fatalf("BuildHandshakeInitiation returned error: %v", err)
	}
	// Verify total length
	if len(pkt) != HandshakeInitiationSize {
		t.Fatalf("expected %d-byte packet, got %d bytes", HandshakeInitiationSize, len(pkt))
	}
	// Verify type byte
	if pkt[0] != TypeHandshakeInitiation {
		t.Errorf("expected type byte 0x%02x, got 0x%02x", TypeHandshakeInitiation, pkt[0])
	}
	// Verify reserved bytes are zero
	for i := 1; i <= 3; i++ {
		if pkt[i] != 0 {
			t.Errorf("reserved byte %d should be zero, got 0x%02x", i, pkt[i])
		}
	}
	// Verify MAC2 (bytes 132-147) is all zeros (no cookie)
	for i := 132; i < 148; i++ {
		if pkt[i] != 0 {
			t.Errorf("mac2 byte %d should be zero, got 0x%02x", i, pkt[i])
		}
	}
	// Sender index (bytes 4-7) should be non-zero with high probability
	senderIndex := pkt[4:8]
	allZero := true
	for _, b := range senderIndex {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("sender index appears to be all-zero (random generation may have failed)")
	}
}

// TestParseHandshakeInitiation verifies that ParseHandshakeInitiation correctly
// parses the built packet and returns the expected field values.
func TestParseHandshakeInitiation(t *testing.T) {
	pkt, err := BuildHandshakeInitiation()
	if err != nil {
		t.Fatalf("BuildHandshakeInitiation returned error: %v", err)
	}
	hi, err := ParseHandshakeInitiation(pkt)
	if err != nil {
		t.Fatalf("ParseHandshakeInitiation returned error: %v", err)
	}
	if hi.Type != TypeHandshakeInitiation {
		t.Errorf("expected type 0x%02x, got 0x%02x", TypeHandshakeInitiation, hi.Type)
	}
	// Reserved bytes should be zero
	for i, b := range hi.Reserved {
		if b != 0 {
			t.Errorf("Reserved[%d] should be 0, got 0x%02x", i, b)
		}
	}
	// MAC2 should be all zeros
	for i, b := range hi.MAC2 {
		if b != 0 {
			t.Errorf("MAC2[%d] should be 0, got 0x%02x", i, b)
		}
	}
}

// TestParseHandshakeInitiationTooShort ensures ParseHandshakeInitiation rejects
// packets shorter than HandshakeInitiationSize.
func TestParseHandshakeInitiationTooShort(t *testing.T) {
	_, err := ParseHandshakeInitiation(make([]byte, 10))
	if err == nil {
		t.Error("expected error for short packet, got nil")
	}
}

// TestParseHandshakeInitiationWrongType ensures ParseHandshakeInitiation returns
// an error when the type byte is not 0x01.
func TestParseHandshakeInitiationWrongType(t *testing.T) {
	pkt := make([]byte, HandshakeInitiationSize)
	pkt[0] = 0x02 // not a Handshake Initiation
	_, err := ParseHandshakeInitiation(pkt)
	if err == nil {
		t.Error("expected error for wrong type byte, got nil")
	}
}
