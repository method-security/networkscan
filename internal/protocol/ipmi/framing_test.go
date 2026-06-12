package ipmi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestBuildRMCPHeader(t *testing.T) {
	got := BuildRMCPHeader()
	want := []byte{0x06, 0x00, 0xFF, 0x07}
	if !bytes.Equal(got, want) {
		t.Fatalf("BuildRMCPHeader() = % x, want % x", got, want)
	}
}

func TestParseRMCPHeader(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		ok   bool
	}{
		{name: "valid", buf: []byte{0x06, 0x00, 0xFF, 0x07, 0xAA}, ok: true},
		{name: "bad version", buf: []byte{0x07, 0x00, 0xFF, 0x07}},
		{name: "bad class", buf: []byte{0x06, 0x00, 0xFF, 0x06}},
		{name: "truncated", buf: []byte{0x06, 0x00, 0xFF}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ParseRMCPHeader(c.buf)
			if c.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestIPMBChecksum(t *testing.T) {
	// Per IPMI spec the IPMB checksum is the two's-complement of the
	// 8-bit sum. {0x20, 0x18} sums to 0x38, two's-complement = 0xC8 —
	// the magic byte the original ipmi.go hand-rolled inline.
	if got, want := IPMBChecksum([]byte{0x20, 0x18}), byte(0xC8); got != want {
		t.Fatalf("IPMBChecksum({0x20,0x18}) = 0x%02x, want 0x%02x", got, want)
	}
	// {0x81, 0x00, 0x38, 0x8E, 0x04} = 0x14B; low byte 0x4B,
	// two's-complement of 0x4B is 0xB5 — the other magic byte.
	if got, want := IPMBChecksum([]byte{0x81, 0x00, 0x38, 0x8E, 0x04}), byte(0xB5); got != want {
		t.Fatalf("IPMBChecksum(...) = 0x%02x, want 0x%02x", got, want)
	}
}

func TestBuildIPMI20SessionHeader(t *testing.T) {
	h := BuildIPMI20SessionHeader(PayloadTypeOpenSessionRequest, 0xDEADBEEF, 0x11223344, 32)
	if len(h) != IPMI20SessionHeaderSize {
		t.Fatalf("header size = %d, want %d", len(h), IPMI20SessionHeaderSize)
	}
	if h[0] != AuthTypeRMCPPlus {
		t.Fatalf("auth type = 0x%02x, want 0x%02x", h[0], AuthTypeRMCPPlus)
	}
	if h[1] != PayloadTypeOpenSessionRequest {
		t.Fatalf("payload type = 0x%02x, want 0x%02x", h[1], PayloadTypeOpenSessionRequest)
	}
	if got := binary.LittleEndian.Uint32(h[2:6]); got != 0xDEADBEEF {
		t.Fatalf("session id = 0x%08x, want 0xDEADBEEF", got)
	}
	if got := binary.LittleEndian.Uint32(h[6:10]); got != 0x11223344 {
		t.Fatalf("session seq = 0x%08x, want 0x11223344", got)
	}
	if got := binary.LittleEndian.Uint16(h[10:12]); got != 32 {
		t.Fatalf("payload len = %d, want 32", got)
	}
}

func TestParseIPMI20PayloadHappy(t *testing.T) {
	// Hand-roll a minimal RMCP envelope + RMCP+ session header + a
	// 4-byte payload, then confirm the parser hands us back exactly
	// those four payload bytes.
	rmcp := BuildRMCPHeader()
	sess := BuildIPMI20SessionHeader(PayloadTypeOpenSessionResponse, 0, 0, 4)
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	full := append(append(append([]byte{}, rmcp...), sess...), payload...)
	got, err := ParseIPMI20Payload(full, PayloadTypeOpenSessionResponse)
	if err != nil {
		t.Fatalf("ParseIPMI20Payload() err = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = % x, want % x", got, payload)
	}
}

func TestParseIPMI20PayloadErrors(t *testing.T) {
	rmcp := BuildRMCPHeader()

	t.Run("wrong payload type", func(t *testing.T) {
		sess := BuildIPMI20SessionHeader(PayloadTypeRAKPMessage2, 0, 0, 0)
		full := append(append([]byte{}, rmcp...), sess...)
		_, err := ParseIPMI20Payload(full, PayloadTypeOpenSessionResponse)
		if err == nil {
			t.Fatalf("expected error on mismatched payload type")
		}
	})

	t.Run("not rmcp+ auth type", func(t *testing.T) {
		sess := BuildIPMI20SessionHeader(PayloadTypeOpenSessionResponse, 0, 0, 0)
		sess[0] = AuthTypeNone
		full := append(append([]byte{}, rmcp...), sess...)
		_, err := ParseIPMI20Payload(full, PayloadTypeOpenSessionResponse)
		if err == nil {
			t.Fatalf("expected error when auth type is not RMCP+")
		}
	})

	t.Run("truncated payload", func(t *testing.T) {
		// Claim 16 bytes of payload but only ship 4.
		sess := BuildIPMI20SessionHeader(PayloadTypeOpenSessionResponse, 0, 0, 16)
		full := append(append(append([]byte{}, rmcp...), sess...), []byte{1, 2, 3, 4}...)
		_, err := ParseIPMI20Payload(full, PayloadTypeOpenSessionResponse)
		if err == nil {
			t.Fatalf("expected truncation error")
		}
		if !errors.Is(err, ErrTruncatedResponse) {
			t.Fatalf("err = %v, want ErrTruncatedResponse wrap", err)
		}
	})
}
