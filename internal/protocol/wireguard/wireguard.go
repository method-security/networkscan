// Package wireguard provides WireGuard protocol packet-building utilities used
// by the enumerate module.
//
// Reference: WireGuard whitepaper https://www.wireguard.com/papers/wireguard.pdf
// and Peter Wu's thesis https://lekensteyn.nl/files/pwu-wireguard-thesis-final.pdf
package wireguard

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// DefaultPort is the standard WireGuard UDP port.
const DefaultPort = 51820

// HandshakeInitiationSize is the fixed size (in bytes) of a WireGuard
// Handshake Initiation message as defined in the WireGuard specification.
//
//	Offset  Length  Field
//	0       1       type = 0x01
//	1       3       reserved (zeros)
//	4       4       sender index (random)
//	8       32      ephemeral public key (random — we don't know the real key)
//	40      48      encrypted static (random — we have no real session context)
//	88      28      encrypted timestamp (random)
//	116     16      mac1 (blake2s keyed, zeroed since we don't have responder pubkey)
//	132     16      mac2 (zeros — no cookie)
const HandshakeInitiationSize = 148

// TypeHandshakeInitiation is the message type byte for a WireGuard Handshake
// Initiation message.
const TypeHandshakeInitiation byte = 0x01

// BuildHandshakeInitiation constructs a 148-byte WireGuard Handshake Initiation
// probe packet.  Because we don't have the real responder public key, mac1 uses
// a zero key — the server will silently drop the message, which is the WHOLE POINT
// of the inference: absence of an ICMP port-unreachable indicates something is
// listening on that UDP port.
func BuildHandshakeInitiation() ([]byte, error) {
	pkt := make([]byte, HandshakeInitiationSize)

	// type = 0x01
	pkt[0] = TypeHandshakeInitiation

	// bytes 1-3: reserved (zero, already zero from make)

	// bytes 4-7: sender index (random)
	if _, err := rand.Read(pkt[4:8]); err != nil {
		return nil, fmt.Errorf("failed to generate sender index: %w", err)
	}

	// bytes 8-39: ephemeral public key (random — no real DH context)
	if _, err := rand.Read(pkt[8:40]); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral pubkey: %w", err)
	}

	// bytes 40-87: encrypted static (random)
	if _, err := rand.Read(pkt[40:88]); err != nil {
		return nil, fmt.Errorf("failed to generate encrypted static: %w", err)
	}

	// bytes 88-115: encrypted timestamp (random)
	if _, err := rand.Read(pkt[88:116]); err != nil {
		return nil, fmt.Errorf("failed to generate encrypted timestamp: %w", err)
	}

	// bytes 116-131: mac1 — should be blake2s("mac1----" || responder_pubkey) keyed
	// hash of the message, but since we don't know the real responder public key,
	// we leave this as zeros.  The server will reject the initiation cryptographically,
	// but will NOT send an ICMP port-unreachable (it silently drops the packet).
	// bytes 132-147: mac2 — zeros (no cookie)

	return pkt, nil
}

// ParseHandshakeInitiation parses a 148-byte WireGuard Handshake Initiation
// packet and returns its constituent fields.  Returns an error if the buffer
// is too short or the type byte is not TypeHandshakeInitiation.
type HandshakeInitiation struct {
	Type               byte
	Reserved           [3]byte
	SenderIndex        uint32
	EphemeralPubKey    [32]byte
	EncryptedStatic    [48]byte
	EncryptedTimestamp [28]byte
	MAC1               [16]byte
	MAC2               [16]byte
}

// ParseHandshakeInitiation parses and validates a raw WireGuard Handshake
// Initiation packet.
func ParseHandshakeInitiation(data []byte) (*HandshakeInitiation, error) {
	if len(data) < HandshakeInitiationSize {
		return nil, fmt.Errorf("packet too short: %d bytes (expected %d)", len(data), HandshakeInitiationSize)
	}
	if data[0] != TypeHandshakeInitiation {
		return nil, fmt.Errorf("unexpected message type: 0x%02x (expected 0x%02x)", data[0], TypeHandshakeInitiation)
	}
	h := &HandshakeInitiation{}
	h.Type = data[0]
	copy(h.Reserved[:], data[1:4])
	h.SenderIndex = binary.LittleEndian.Uint32(data[4:8])
	copy(h.EphemeralPubKey[:], data[8:40])
	copy(h.EncryptedStatic[:], data[40:88])
	copy(h.EncryptedTimestamp[:], data[88:116])
	copy(h.MAC1[:], data[116:132])
	copy(h.MAC2[:], data[132:148])
	return h, nil
}
