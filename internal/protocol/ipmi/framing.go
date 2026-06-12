// Package ipmi implements IPMI 1.5 and IPMI 2.0 (RMCP+) framing
// primitives used by the networkscan discovery plugin to send the three
// pre-auth probes — Get-Channel-Auth-Capabilities, Cipher-Zero Open
// Session (CVE-2013-4031), and RAKP-1/RAKP-2 (CVE-2013-4786).
//
// The wire formats are defined by the IPMI 2.0 specification, primarily
// section 13 (RMCP and IPMI session framing) and section 13.20 (RMCP+
// session formats and Open Session / RAKP exchange).
package ipmi

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// RMCP wrapper constants. RMCP is the outer transport for both IPMI 1.5
// and IPMI 2.0 sessions on UDP/623.
const (
	RMCPVersion   byte = 0x06 // RMCP version 1.0
	RMCPSeqNoACK  byte = 0xFF // Sequence value meaning "no RMCP-level ACK requested"
	RMCPClassIPMI byte = 0x07 // Message class: IPMI
)

// IPMI session auth-type values for the v1.5 session header. For the
// outer wrapper of an unauthenticated v1.5 message and for the RMCP+
// envelope this value is either AuthTypeNone (v1.5) or AuthTypeRMCPPlus
// (v2.0).
const (
	AuthTypeNone     byte = 0x00
	AuthTypeMD2      byte = 0x01
	AuthTypeMD5      byte = 0x02
	AuthTypeStraight byte = 0x04
	AuthTypeOEM      byte = 0x05
	AuthTypeRMCPPlus byte = 0x06
)

// IPMI 2.0 RMCP+ payload types. The payload-type byte sits at offset 5
// of the v2.0 session header. We only need the open-session and RAKP
// types for the deep probe.
const (
	PayloadTypeOpenSessionRequest  byte = 0x10
	PayloadTypeOpenSessionResponse byte = 0x11
	PayloadTypeRAKPMessage1        byte = 0x12
	PayloadTypeRAKPMessage2        byte = 0x13
	PayloadTypeRAKPMessage3        byte = 0x14
	PayloadTypeRAKPMessage4        byte = 0x15
)

// RMCP+ status codes. Status 0x00 is success; any non-zero value
// indicates a session-level error from the BMC (per IPMI 2.0 §13.24).
const (
	RMCPPlusStatusNoErrors                   byte = 0x00
	RMCPPlusStatusInsufficientResources      byte = 0x01
	RMCPPlusStatusInvalidSessionID           byte = 0x02
	RMCPPlusStatusInvalidPayloadType         byte = 0x03
	RMCPPlusStatusInvalidAuthAlgorithm       byte = 0x04
	RMCPPlusStatusInvalidIntegrityAlgorithm  byte = 0x05
	RMCPPlusStatusNoMatchingAuthPayload      byte = 0x06
	RMCPPlusStatusNoMatchingIntegrityPayload byte = 0x07
	RMCPPlusStatusInvalidSessionIDOpenSess   byte = 0x08
	RMCPPlusStatusInvalidRoleField           byte = 0x09
	RMCPPlusStatusUnauthorizedRole           byte = 0x0A
	RMCPPlusStatusInsufficientResourcesRole  byte = 0x0B
	RMCPPlusStatusInvalidNameLength          byte = 0x0C
	RMCPPlusStatusUnauthorizedName           byte = 0x0D
)

// Cipher suite component algorithm IDs (IPMI 2.0 §13.28). We hardcode
// the values we care about; Cipher Suite 0 is "all algorithms NONE",
// Cipher Suite 3 is HMAC-SHA1 / HMAC-SHA1-96 / AES-CBC-128.
const (
	AuthAlgorithmRAKPNone     byte = 0x00
	AuthAlgorithmRAKPHMACSHA1 byte = 0x01

	IntegrityAlgorithmNone       byte = 0x00
	IntegrityAlgorithmHMACSHA196 byte = 0x01

	ConfidentialityAlgorithmNone      byte = 0x00
	ConfidentialityAlgorithmAESCBC128 byte = 0x01
)

// RMCP/IPMI session-header sizes. Useful as named constants instead of
// the magic numbers the parsers would otherwise be peppered with.
const (
	RMCPHeaderSize          = 4  // 0x06, reserved, seq, class
	IPMI15SessionHeaderSize = 10 // authtype(1) + seq(4) + sid(4) + msglen(1)
	IPMI20SessionHeaderSize = 12 // authtype(1) + payload_type(1) + sid(4) + seq(4) + payload_len(2)
)

// BuildRMCPHeader builds the 4-byte RMCP envelope header used by every
// IPMI message we send on UDP/623.
func BuildRMCPHeader() []byte {
	return []byte{RMCPVersion, 0x00, RMCPSeqNoACK, RMCPClassIPMI}
}

// BuildIPMI15SessionHeader builds the unauthenticated IPMI v1.5 session
// header used for Get-Channel-Auth-Capabilities. msgLen is the length
// of the IPMB message bytes that will follow this header.
func BuildIPMI15SessionHeader(msgLen byte) []byte {
	return []byte{
		AuthTypeNone,           // authentication type
		0x00, 0x00, 0x00, 0x00, // session sequence number (zero pre-session)
		0x00, 0x00, 0x00, 0x00, // session ID (zero pre-session)
		msgLen, // message length
	}
}

// BuildIPMI20SessionHeader builds the RMCP+ session header used for
// open-session and RAKP exchanges. payloadType is one of the
// PayloadType* constants. The payload itself follows the returned
// header bytes. sessionID and sessionSeq are both zero for the
// open-session and RAKP-1 messages we send (we have no established
// session yet); the BMC also returns zero in its responses for these
// payload types.
func BuildIPMI20SessionHeader(payloadType byte, sessionID, sessionSeq uint32, payloadLen uint16) []byte {
	header := make([]byte, IPMI20SessionHeaderSize)
	header[0] = AuthTypeRMCPPlus
	header[1] = payloadType
	binary.LittleEndian.PutUint32(header[2:6], sessionID)
	binary.LittleEndian.PutUint32(header[6:10], sessionSeq)
	binary.LittleEndian.PutUint16(header[10:12], payloadLen)
	return header
}

// IPMBChecksum returns the IPMB two's-complement checksum over the
// given bytes. The IPMI spec defines this as `(-sum) mod 256`, which
// for a uint8 is equivalent to the bitwise two's-complement (^sum + 1).
func IPMBChecksum(data []byte) byte {
	var sum byte
	for _, b := range data {
		sum += b
	}
	return (^sum) + 1
}

// ParseRMCPHeader validates the 4-byte RMCP envelope on the inbound
// response. It returns an error if the version or class field is
// wrong, indicating the response is not an IPMI message.
func ParseRMCPHeader(buf []byte) error {
	if len(buf) < RMCPHeaderSize {
		return fmt.Errorf("rmcp: response too short (%d < %d)", len(buf), RMCPHeaderSize)
	}
	if buf[0] != RMCPVersion {
		return fmt.Errorf("rmcp: unexpected version 0x%02x", buf[0])
	}
	if buf[3] != RMCPClassIPMI {
		return fmt.Errorf("rmcp: unexpected message class 0x%02x", buf[3])
	}
	return nil
}

// ErrTruncatedResponse signals that the response is too short to parse
// the field the caller wants. Plugin code uses errors.Is to decide
// whether to keep going with a partial result or fail.
var ErrTruncatedResponse = errors.New("ipmi: response truncated")

// ParseIPMI20Payload validates the RMCP envelope + RMCP+ session
// header on an inbound v2.0 response and returns the payload bytes
// (the part after the session header). It enforces that the payload
// type matches what the caller is expecting.
func ParseIPMI20Payload(buf []byte, expectedPayloadType byte) ([]byte, error) {
	if err := ParseRMCPHeader(buf); err != nil {
		return nil, err
	}
	if len(buf) < RMCPHeaderSize+IPMI20SessionHeaderSize {
		return nil, fmt.Errorf("%w: %d < %d", ErrTruncatedResponse, len(buf), RMCPHeaderSize+IPMI20SessionHeaderSize)
	}
	sess := buf[RMCPHeaderSize:]
	if sess[0] != AuthTypeRMCPPlus {
		return nil, fmt.Errorf("ipmi20: response auth_type 0x%02x is not RMCP+ (0x06)", sess[0])
	}
	if sess[1] != expectedPayloadType {
		return nil, fmt.Errorf("ipmi20: payload type 0x%02x != expected 0x%02x", sess[1], expectedPayloadType)
	}
	payloadLen := binary.LittleEndian.Uint16(sess[10:12])
	payloadStart := RMCPHeaderSize + IPMI20SessionHeaderSize
	payloadEnd := payloadStart + int(payloadLen)
	if payloadEnd > len(buf) {
		return nil, fmt.Errorf("%w: payload claims %d bytes but only %d available", ErrTruncatedResponse, payloadLen, len(buf)-payloadStart)
	}
	return buf[payloadStart:payloadEnd], nil
}
