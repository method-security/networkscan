package ike

import (
	"encoding/binary"
	"testing"
)

func TestBuildIKEv2SAInitRequestUses3DESEncryptionID(t *testing.T) {
	packet := BuildIKEv2SAInitRequest()
	if len(packet) < 48 {
		t.Fatalf("packet too short: got %d bytes", len(packet))
	}

	// IKE header (28) + SA header (4) + Proposal header (8) = 40.
	// First transform ID lives at bytes 6..7 of the 8-byte transform entry.
	const firstTransformIDOffset = 40 + 6
	got := binary.BigEndian.Uint16(packet[firstTransformIDOffset : firstTransformIDOffset+2])
	if got != 3 {
		t.Fatalf("unexpected encryption transform ID: got %d, want 3 (ENCR_3DES)", got)
	}
}

func TestGetEncryptionAlgorithmNameUsesIKEv2Registry(t *testing.T) {
	tests := []struct {
		id   uint16
		want string
	}{
		{1, "DES-IV64"},
		{2, "DES"},
		{3, "3DES-CBC"},
		{5, "IDEA-CBC"},
		{6, "CAST-CBC"},
		{7, "Blowfish-CBC"},
	}

	for _, tt := range tests {
		if got := GetEncryptionAlgorithmName(tt.id); got != tt.want {
			t.Fatalf("GetEncryptionAlgorithmName(%d) = %q, want %q", tt.id, got, tt.want)
		}
	}
}
