package dahuadhip

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// buildDhipFrame prefixes a JSON-RPC body with the 32-byte DHIP header.
// sessionID is the echo cookie carried on the connection (0 for the initial
// probe).  The header's two length words are identical on stock firmware.
func buildDhipFrame(body []byte, sessionID uint64) []byte {
	frame := make([]byte, dhipHeaderLen+len(body))
	copy(frame[0:8], dhipMagic)
	binary.LittleEndian.PutUint64(frame[8:16], sessionID)
	binary.LittleEndian.PutUint32(frame[16:20], uint32(len(body)))
	binary.LittleEndian.PutUint32(frame[20:24], uint32(len(body)))
	// bytes 24-31 are reserved zeros
	copy(frame[dhipHeaderLen:], body)
	return frame
}

// validateDhipHeader validates just the 32-byte DHIP header.  Used by the
// driver after reading exactly dhipHeaderLen bytes off the wire, BEFORE
// reading the body — splitting header-and-body validation lets the caller
// surface "wrong protocol on TCP/37777" earlier without allocating a
// body-sized buffer first.  Returns the body length declared in the header.
func validateDhipHeader(hdr []byte) (uint32, error) {
	if len(hdr) < dhipHeaderLen {
		return 0, fmt.Errorf("DHIP header truncated: %d < %d", len(hdr), dhipHeaderLen)
	}
	if !bytes.Equal(hdr[0:8], dhipMagic) {
		return 0, fmt.Errorf("DHIP magic mismatch: got %x, expected %x", hdr[0:8], dhipMagic)
	}
	bodyLen := binary.LittleEndian.Uint32(hdr[16:20])
	bodyLenDup := binary.LittleEndian.Uint32(hdr[20:24])
	if bodyLen != bodyLenDup {
		return 0, fmt.Errorf("DHIP length disagreement: %d != %d", bodyLen, bodyLenDup)
	}
	if bodyLen == 0 {
		return 0, fmt.Errorf("DHIP body length is zero")
	}
	if int(bodyLen) > dhipResponseBodyCap {
		return 0, fmt.Errorf("DHIP body length %d exceeds cap %d", bodyLen, dhipResponseBodyCap)
	}
	return bodyLen, nil
}

// parseDhipFrame validates a complete DHIP frame (header + body) and returns
// the JSON-RPC body slice.  Convenience helper for tests where the entire
// frame is constructed in-memory.
func parseDhipFrame(data []byte) ([]byte, error) {
	bodyLen, err := validateDhipHeader(data)
	if err != nil {
		return nil, err
	}
	available := len(data) - dhipHeaderLen
	if available < int(bodyLen) {
		return nil, fmt.Errorf("DHIP body truncated: %d available, %d declared", available, bodyLen)
	}
	return data[dhipHeaderLen : dhipHeaderLen+int(bodyLen)], nil
}

// dhipLoginResponse models the JSON-RPC error response Dahua firmware emits in
// reply to an empty-credential `global.login` attempt.  All fields are optional
// because we tolerate firmware-variant differences silently — the absence of a
// field is itself a fingerprint signal.
type dhipLoginResponse struct {
	ID      *int   `json:"id,omitempty"`
	Session *int64 `json:"session,omitempty"`
	Error   *struct {
		Code    *int    `json:"code,omitempty"`
		Message *string `json:"message,omitempty"`
	} `json:"error,omitempty"`
	Params *struct {
		Encryption *string `json:"encryption,omitempty"`
		Random     *string `json:"random,omitempty"`
		Realm      *string `json:"realm,omitempty"`
	} `json:"params,omitempty"`
	Result *bool `json:"result,omitempty"`
}

// parseLoginResponse decodes the JSON-RPC body of a Dahua global.login reply.
// Returns nil + nil when the body is not parseable JSON; callers should treat
// that as "DHIP framing confirmed but the listener is not stock Dahua firmware."
func parseLoginResponse(body []byte) (*dhipLoginResponse, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, fmt.Errorf("empty JSON-RPC body")
	}
	var resp dhipLoginResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// realmLooksLikePlainSerial returns true when the realm string matches the
// legacy Dahua plaintext-serial format (12-16 char uppercase alphanumeric).
// Returns false for the 32-char hex realm shape used on 2019+ firmware (the
// hash is the same length irrespective of the underlying serial).
func realmLooksLikePlainSerial(realm string) bool {
	n := len(realm)
	if n < realmPlaintextSerialMinLen || n > realmPlaintextSerialMaxLen {
		return false
	}
	for _, r := range realm {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		default:
			return false
		}
	}
	return true
}
