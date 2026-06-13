package nebula

import (
	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
)

// ToFernPacketType converts an internal Nebula packet type integer to the
// Fern-generated NebulaPacketType enum value.
func ToFernPacketType(t int) (commonprotocolfern.NebulaPacketType, bool) {
	switch t {
	case PacketTypeHandshake:
		return commonprotocolfern.NebulaPacketTypeHandshake, true
	case PacketTypeMessage:
		return commonprotocolfern.NebulaPacketTypeMessage, true
	case PacketTypeRecvError:
		return commonprotocolfern.NebulaPacketTypeRecvError, true
	case PacketTypeLighthouse:
		return commonprotocolfern.NebulaPacketTypeLighthouse, true
	case PacketTypeTest:
		return commonprotocolfern.NebulaPacketTypeTest, true
	case PacketTypeCloseTunnel:
		return commonprotocolfern.NebulaPacketTypeCloseTunnel, true
	}
	return "", false
}

// ToFernHeader converts an internal Header to the Fern-generated NebulaHeader type.
// Returns nil if hdr is nil or if the packet type cannot be mapped.
func ToFernHeader(hdr *Header) *commonprotocolfern.NebulaHeader {
	if hdr == nil {
		return nil
	}
	fernType, ok := ToFernPacketType(hdr.Type)
	if !ok {
		return nil
	}
	return &commonprotocolfern.NebulaHeader{
		Version:        hdr.Version,
		Type:           fernType,
		Subtype:        hdr.Subtype,
		Reserved:       hdr.Reserved,
		RemoteIndex:    int64(hdr.RemoteIndex),
		MessageCounter: int64(hdr.MessageCounter),
	}
}
