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

// makeIKEv1InformationalWithNotify builds a minimal IKEv1 Informational packet
// with a single Notification payload carrying the given notify type.
func makeIKEv1InformationalWithNotify(notifyType uint16) []byte {
	// Notification payload: generic header (4) + DOI (4) + Protocol-ID (1) + SPI-size (1) + Notify type (2) = 12 bytes
	notify := make([]byte, 12)
	notify[0] = 0 // next payload: none
	binary.BigEndian.PutUint16(notify[2:4], 12)        // payload length
	binary.BigEndian.PutUint32(notify[4:8], 1)         // DOI: IPSEC
	notify[8] = 0                                      // Protocol-ID
	notify[9] = 0                                      // SPI size
	binary.BigEndian.PutUint16(notify[10:12], notifyType)
	packet := make([]byte, 28)
	packet[16] = 11   // next payload: Notification
	packet[17] = 1 << 4 // IKEv1
	packet[18] = 5    // exchange type: Informational
	binary.BigEndian.PutUint32(packet[24:28], uint32(28+len(notify)))
	return append(packet, notify...)
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
			name:               "ikev1_informational_no_payload",
			packet:             makeIKEHeader(1, 5),
			wantAggressiveMode: false,
			wantIkev1Supported: true,
		},
		{
			name:               "ikev1_informational_invalid_exchange_type",
			packet:             makeIKEv1InformationalWithNotify(7),
			wantAggressiveMode: false,
			wantIkev1Supported: true,
		},
		{
			name:               "ikev1_informational_no_proposal_chosen",
			packet:             makeIKEv1InformationalWithNotify(14),
			wantAggressiveMode: true,
			wantIkev1Supported: true,
		},
		{
			name:               "ikev1_informational_invalid_id_information",
			packet:             makeIKEv1InformationalWithNotify(18),
			wantAggressiveMode: true,
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
