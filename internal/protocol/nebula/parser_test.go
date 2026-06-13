package nebula

import (
	"errors"
	"testing"
)

// validHandshakeHeader is a 16-byte fixture for a well-formed Nebula Handshake header.
// Layout: version=1, type=1 (HANDSHAKE) → byte0=0x11
//
//	subtype=0 → byte1=0x00
//	reserved=0 → bytes2-3=0x0000
//	remoteIndex=0xDEADBEEF → bytes4-7
//	messageCounter=1 → bytes8-15
var validHandshakeHeader = []byte{
	0x11,       // version=1, type=1 (HANDSHAKE)
	0x00,       // subtype=0
	0x00, 0x00, // reserved=0
	0xDE, 0xAD, 0xBE, 0xEF, // remoteIndex=0xDEADBEEF
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // messageCounter=1
}

// validRecvErrorHeader is a 16-byte fixture for a RecvError response.
// type=5 (RECV_ERROR) → byte0=0x15
var validRecvErrorHeader = []byte{
	0x15,       // version=1, type=5 (RECV_ERROR)
	0x00,       // subtype=0
	0x00, 0x00, // reserved=0
	0xCA, 0xFE, 0xBA, 0xBE, // remoteIndex=0xCAFEBABE
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // messageCounter=2
}

// wrongVersionHeader has version bits set to 2 instead of 1.
var wrongVersionHeader = []byte{
	0x21,       // version=2, type=1
	0x00,       // subtype=0
	0x00, 0x00, // reserved=0
	0x00, 0x00, 0x00, 0x00, // remoteIndex=0
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // messageCounter=0
}

func TestParseHeader_ValidHandshake(t *testing.T) {
	hdr, err := ParseHeader(validHandshakeHeader)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if hdr.Version != 1 {
		t.Errorf("version: want 1, got %d", hdr.Version)
	}
	if hdr.Type != PacketTypeHandshake {
		t.Errorf("type: want %d, got %d", PacketTypeHandshake, hdr.Type)
	}
	if hdr.Subtype != 0 {
		t.Errorf("subtype: want 0, got %d", hdr.Subtype)
	}
	if hdr.Reserved != 0 {
		t.Errorf("reserved: want 0, got %d", hdr.Reserved)
	}
	if hdr.RemoteIndex != 0xDEADBEEF {
		t.Errorf("remoteIndex: want 0xDEADBEEF, got 0x%X", hdr.RemoteIndex)
	}
	if hdr.MessageCounter != 1 {
		t.Errorf("messageCounter: want 1, got %d", hdr.MessageCounter)
	}
}

func TestParseHeader_TooShort(t *testing.T) {
	short := validHandshakeHeader[:8]
	_, err := ParseHeader(short)
	if !errors.Is(err, ErrTooShort) {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestParseHeader_WrongVersion(t *testing.T) {
	_, err := ParseHeader(wrongVersionHeader)
	if !errors.Is(err, ErrInvalidVersion) {
		t.Errorf("expected ErrInvalidVersion, got %v", err)
	}
}

func TestParseHeader_RecvError(t *testing.T) {
	hdr, err := ParseHeader(validRecvErrorHeader)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !IsRecvError(hdr) {
		t.Errorf("IsRecvError should be true for type %d", hdr.Type)
	}
	if IsHandshake(hdr) {
		t.Errorf("IsHandshake should be false for RecvError packet")
	}
}

func TestBuildHandshakeInitiation_Length(t *testing.T) {
	pkt, err := BuildHandshakeInitiation()
	if err != nil {
		t.Fatalf("BuildHandshakeInitiation error: %v", err)
	}
	want := HeaderLen + HandshakePayloadLen // 16 + 50 = 66
	if len(pkt) != want {
		t.Errorf("packet length: want %d, got %d", want, len(pkt))
	}
}

func TestBuildHandshakeInitiation_Type(t *testing.T) {
	pkt, err := BuildHandshakeInitiation()
	if err != nil {
		t.Fatalf("BuildHandshakeInitiation error: %v", err)
	}
	// Upper nibble of byte 0 should be version=1; lower nibble should be type=1 (HANDSHAKE)
	version := int((pkt[0] & 0xF0) >> 4)
	pktType := int(pkt[0] & 0x0F)
	if version != 1 {
		t.Errorf("version nibble: want 1, got %d", version)
	}
	if pktType != PacketTypeHandshake {
		t.Errorf("type nibble: want %d (HANDSHAKE), got %d", PacketTypeHandshake, pktType)
	}
}

func TestBuildHandshakeInitiation_MessageCounter(t *testing.T) {
	pkt, err := BuildHandshakeInitiation()
	if err != nil {
		t.Fatalf("BuildHandshakeInitiation error: %v", err)
	}
	// Bytes 8-15 are the messageCounter in big-endian; should be 1.
	var counter uint64
	for i := 0; i < 8; i++ {
		counter = (counter << 8) | uint64(pkt[8+i])
	}
	if counter != 1 {
		t.Errorf("messageCounter: want 1, got %d", counter)
	}
}

func TestIsHandshake(t *testing.T) {
	hdr, _ := ParseHeader(validHandshakeHeader)
	if !IsHandshake(hdr) {
		t.Error("IsHandshake should return true for a HANDSHAKE type")
	}
}

func TestIsHandshake_Nil(t *testing.T) {
	if IsHandshake(nil) {
		t.Error("IsHandshake(nil) should return false")
	}
}

func TestIsRecvError_Nil(t *testing.T) {
	if IsRecvError(nil) {
		t.Error("IsRecvError(nil) should return false")
	}
}
