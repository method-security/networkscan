package ike

import (
	"encoding/binary"
	"testing"
)

func makeIKEHeader(majorVersion, exchangeType byte) []byte {
	packet := make([]byte, 28)
	packet[17] = majorVersion << 4
	packet[18] = exchangeType
	binary.BigEndian.PutUint32(packet[24:28], uint32(len(packet)))
	return packet
}

func TestIsIKEv1AggressiveResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		packet                 []byte
		wantAggressiveMode     bool
		wantIkev1Supported     bool
	}{
		{
			name:               "ikev1_aggressive_mode_exchange",
			packet:             makeIKEHeader(1, 4),
			wantAggressiveMode: true,
			wantIkev1Supported: true,
		},
		{
			name:               "ikev1_informational_exchange",
			packet:             makeIKEHeader(1, 5),
			wantAggressiveMode: false,
			wantIkev1Supported: true,
		},
		{
			name:               "ikev2_response",
			packet:             makeIKEHeader(2, 34),
			wantAggressiveMode: false,
			wantIkev1Supported: false,
		},
		{
			name: "invalid_length_field",
			packet: func() []byte {
				p := makeIKEHeader(1, 4)
				binary.BigEndian.PutUint32(p[24:28], uint32(len(p)+8))
				return p
			}(),
			wantAggressiveMode: false,
			wantIkev1Supported: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotAggressiveMode, gotIkev1Supported := isIKEv1AggressiveResponse(tt.packet)
			if gotAggressiveMode != tt.wantAggressiveMode {
				t.Fatalf("aggressiveMode = %v, want %v", gotAggressiveMode, tt.wantAggressiveMode)
			}
			if gotIkev1Supported != tt.wantIkev1Supported {
				t.Fatalf("ikev1Supported = %v, want %v", gotIkev1Supported, tt.wantIkev1Supported)
			}
		})
	}
}
