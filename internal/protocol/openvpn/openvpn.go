// Package openvpn provides OpenVPN protocol parsing and packet-building utilities
// used by the enumerate module.
package openvpn

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// OpenVPN control-channel opcodes (top 5 bits of the first byte, shifted left 3).
const (
	POpcodeShift              uint8 = 3
	PControlHardResetClientV2 uint8 = 7
	PControlHardResetServerV2 uint8 = 8
	SessionIDLength                 = 8
)

// DefaultPort is the standard OpenVPN UDP port.
const DefaultPort = 1194

// ControlPacket represents a parsed OpenVPN control-channel packet.
type ControlPacket struct {
	Opcode    uint8
	KeyID     uint8
	SessionID [SessionIDLength]byte
	// MessagePacketIDArrayLen is the number of ack'd packet IDs that follow.
	MessagePacketIDArrayLen uint8
	// MessagePacketID is the packet-ID of this packet.
	MessagePacketID uint32
}

// HardResetClientV2Size is the size in bytes of the HARD_RESET_CLIENT_V2 packet:
// 1 opcode + 8 session_id + 1 ack_array_len + 4 message_packet_id = 14.
const HardResetClientV2Size = 14

// BuildHardResetClientV2 constructs the 14-byte HARD_RESET_CLIENT_V2 control packet
// used to initiate a UDP OpenVPN handshake.
//
//	Byte 0    : opcode(7) << 3 | key_id(0)
//	Bytes 1–8 : random session ID
//	Byte 9    : ack-array length (0)
//	Bytes 10–13: message packet-ID (0)
func BuildHardResetClientV2() ([]byte, error) {
	pkt := make([]byte, HardResetClientV2Size)
	pkt[0] = PControlHardResetClientV2 << POpcodeShift // opcode | key_id
	if _, err := rand.Read(pkt[1 : 1+SessionIDLength]); err != nil {
		return nil, fmt.Errorf("failed to generate random session ID: %w", err)
	}
	pkt[9] = 0x00 // ack-array length
	binary.BigEndian.PutUint32(pkt[10:14], 0)
	return pkt, nil
}

// BuildTCPHardResetClientV2 wraps the UDP control packet in the OpenVPN-over-TCP
// length-prefix framing. Per the OpenVPN wire format, TCP frames are prefixed with
// a 2-byte big-endian packet length (NOT including the 2 length bytes themselves).
func BuildTCPHardResetClientV2() ([]byte, error) {
	udp, err := BuildHardResetClientV2()
	if err != nil {
		return nil, err
	}
	framed := make([]byte, 2+len(udp))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(udp)))
	copy(framed[2:], udp)
	return framed, nil
}

// ParseControlPacket parses a raw OpenVPN control-channel packet (UDP framing —
// the length prefix must be stripped before calling this function for TCP).
// Returns an error if the packet is too short or the opcode is unrecognised.
func ParseControlPacket(data []byte) (*ControlPacket, error) {
	const minLen = 10 // 1 opcode + 8 session ID + 1 ack len
	if len(data) < minLen {
		return nil, fmt.Errorf("packet too short: %d bytes (need at least %d)", len(data), minLen)
	}
	pkt := &ControlPacket{}
	pkt.Opcode = data[0] >> POpcodeShift
	pkt.KeyID = data[0] & 0x07
	copy(pkt.SessionID[:], data[1:1+SessionIDLength])
	pkt.MessagePacketIDArrayLen = data[9]
	offset := 10 + int(pkt.MessagePacketIDArrayLen)*4
	if len(data) >= offset+4 {
		pkt.MessagePacketID = binary.BigEndian.Uint32(data[offset : offset+4])
	}
	return pkt, nil
}

// IsHardResetServer returns true when the packet carries the HARD_RESET_SERVER_V2 opcode,
// indicating an OpenVPN server has acknowledged our client reset.
func IsHardResetServer(pkt *ControlPacket) bool {
	return pkt.Opcode == PControlHardResetServerV2
}

// ContainsSessionID reports whether the raw response bytes contain the given 8-byte
// client session ID, which OpenVPN servers echo back in the HARD_RESET_SERVER_V2.
func ContainsSessionID(response []byte, sessionID [SessionIDLength]byte) bool {
	id := sessionID[:]
	for i := 0; i <= len(response)-SessionIDLength; i++ {
		match := true
		for j := 0; j < SessionIDLength; j++ {
			if response[i+j] != id[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
