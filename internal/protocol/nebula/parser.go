// Package nebula provides Nebula overlay network protocol parsing and packet-building
// utilities for detecting Nebula lighthouse services via UDP handshake probing.
package nebula

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// Nebula packet type constants matching the Nebula header specification.
const (
	PacketTypeHandshake   = 1
	PacketTypeMessage     = 2
	PacketTypeLighthouse  = 3
	PacketTypeTest        = 4
	PacketTypeRecvError   = 5
	PacketTypeCloseTunnel = 6

	// DefaultPort is the standard Nebula lighthouse UDP port.
	DefaultPort = 4242

	// HeaderLen is the fixed Nebula header length in bytes.
	// Layout: version(4b)|type(4b)|subtype(8b)|reserved(16b)|remoteIndex(32b)|messageCounter(64b)
	HeaderLen = 16

	// HandshakePayloadLen is the number of dummy Noise IK payload bytes appended
	// to the handshake initiation packet to provoke a response.
	HandshakePayloadLen = 50
)

// ErrTooShort is returned when the input buffer is shorter than HeaderLen.
var ErrTooShort = errors.New("nebula: packet too short for header")

// ErrInvalidVersion is returned when the parsed version field is not 1.
var ErrInvalidVersion = errors.New("nebula: invalid version in header")

// Header represents the parsed 16-byte Nebula fixed header.
type Header struct {
	Version        int
	Type           int
	Subtype        int
	Reserved       int
	RemoteIndex    uint32
	MessageCounter uint64
}

// ParseHeader parses the first 16 bytes of data into a Nebula Header.
// Returns ErrTooShort if len(data) < 16 and ErrInvalidVersion if version != 1.
func ParseHeader(data []byte) (*Header, error) {
	if len(data) < HeaderLen {
		return nil, ErrTooShort
	}

	// Byte 0: upper nibble = version, lower nibble = type
	version := int((data[0] & 0xF0) >> 4)
	pktType := int(data[0] & 0x0F)

	// Byte 1: subtype
	subtype := int(data[1])

	// Bytes 2-3: reserved (big-endian uint16)
	reserved := int(binary.BigEndian.Uint16(data[2:4]))

	// Bytes 4-7: remoteIndex (big-endian uint32)
	remoteIndex := binary.BigEndian.Uint32(data[4:8])

	// Bytes 8-15: messageCounter (big-endian uint64)
	messageCounter := binary.BigEndian.Uint64(data[8:16])

	if version != 1 {
		return nil, ErrInvalidVersion
	}

	return &Header{
		Version:        version,
		Type:           pktType,
		Subtype:        subtype,
		Reserved:       reserved,
		RemoteIndex:    remoteIndex,
		MessageCounter: messageCounter,
	}, nil
}

// IsRecvError reports whether hdr represents a RecvError packet.
func IsRecvError(hdr *Header) bool {
	return hdr != nil && hdr.Type == PacketTypeRecvError
}

// IsHandshake reports whether hdr represents a Handshake packet.
func IsHandshake(hdr *Header) bool {
	return hdr != nil && hdr.Type == PacketTypeHandshake
}

// BuildHandshakeInitiation builds a Nebula handshake initiation packet.
// The packet consists of a 16-byte header (type=Handshake, subtype=0,
// random remoteIndex, messageCounter=1) followed by HandshakePayloadLen bytes
// of crypto/rand data to simulate a Noise IK ephemeral key payload.
// Total length: HeaderLen + HandshakePayloadLen = 66 bytes.
func BuildHandshakeInitiation() ([]byte, error) {
	pkt := make([]byte, HeaderLen+HandshakePayloadLen)

	// Byte 0: version=1 (upper nibble) | type=Handshake (lower nibble)
	pkt[0] = byte((1 << 4) | PacketTypeHandshake)
	// Byte 1: subtype = 0
	pkt[1] = 0
	// Bytes 2-3: reserved = 0
	binary.BigEndian.PutUint16(pkt[2:4], 0)

	// Bytes 4-7: remoteIndex — random to avoid replay
	var idxBuf [4]byte
	if _, err := rand.Read(idxBuf[:]); err != nil {
		return nil, err
	}
	copy(pkt[4:8], idxBuf[:])

	// Bytes 8-15: messageCounter = 1
	binary.BigEndian.PutUint64(pkt[8:16], 1)

	// Bytes 16+: dummy Noise IK payload
	if _, err := rand.Read(pkt[16:]); err != nil {
		return nil, err
	}

	return pkt, nil
}
