package ipmi

import (
	"encoding/binary"
	"fmt"
)

// CipherZero is the well-known IPMI-2.0 cipher-suite identifier
// (alg-auth=NONE, alg-integrity=NONE, alg-confidentiality=NONE) at the
// heart of CVE-2013-4031. A BMC that accepts an Open Session Request
// for this suite is exploitable: any subsequent IPMI commands run as
// the user named in RAKP-1 with no authentication at all.

// OpenSessionPayloadSize is the on-the-wire size of the Open Session
// Request payload (per IPMI 2.0 §13.17).
const OpenSessionPayloadSize = 32

// openSessionPayloadTypeAuthentication / Integrity / Confidentiality
// identify the three nested payload records that follow the open-
// session header bytes.
const (
	openSessionPayloadTypeAuthentication  byte = 0x00
	openSessionPayloadTypeIntegrity       byte = 0x01
	openSessionPayloadTypeConfidentiality byte = 0x02

	openSessionNestedPayloadLength byte = 0x08
)

// Privilege level requests for RMCP+ Open Session.
const (
	PrivilegeHighest       byte = 0x00 // BMC decides
	PrivilegeCallback      byte = 0x01
	PrivilegeUser          byte = 0x02
	PrivilegeOperator      byte = 0x03
	PrivilegeAdministrator byte = 0x04
)

// BuildOpenSessionRequest assembles the RMCP+ Open Session Request
// pre-RAKP, picking the cipher suite components from the supplied
// algorithm IDs. For cipher zero pass 0x00 for all three; for the
// HMAC-SHA1 / SHA1-96 / AES-CBC-128 suite (cipher suite 3, used by
// the RAKP existence-oracle probe) pass 0x01 for all three. The
// consoleSessionID must be non-zero and is what the BMC will echo.
func BuildOpenSessionRequest(messageTag byte, requestedPrivilege byte, consoleSessionID uint32,
	authAlg, integrityAlg, confidentialityAlg byte) []byte {
	payload := make([]byte, OpenSessionPayloadSize)
	payload[0] = messageTag
	payload[1] = requestedPrivilege
	// 2-3 reserved
	binary.LittleEndian.PutUint32(payload[4:8], consoleSessionID)

	// Authentication payload (offset 8-15).
	payload[8] = openSessionPayloadTypeAuthentication
	// 9-10 reserved
	payload[11] = openSessionNestedPayloadLength
	payload[12] = authAlg
	// 13-15 reserved

	// Integrity payload (offset 16-23).
	payload[16] = openSessionPayloadTypeIntegrity
	// 17-18 reserved
	payload[19] = openSessionNestedPayloadLength
	payload[20] = integrityAlg
	// 21-23 reserved

	// Confidentiality payload (offset 24-31).
	payload[24] = openSessionPayloadTypeConfidentiality
	// 25-26 reserved
	payload[27] = openSessionNestedPayloadLength
	payload[28] = confidentialityAlg
	// 29-31 reserved

	rmcp := BuildRMCPHeader()
	sess := BuildIPMI20SessionHeader(PayloadTypeOpenSessionRequest, 0, 0, uint16(OpenSessionPayloadSize))

	out := make([]byte, 0, len(rmcp)+len(sess)+len(payload))
	out = append(out, rmcp...)
	out = append(out, sess...)
	out = append(out, payload...)
	return out
}

// BuildCipherZeroOpenSessionRequest is the CVE-2013-4031 specialisation
// of BuildOpenSessionRequest with all three algorithms set to NONE.
// A BMC that returns status 0x00 here is critically misconfigured.
func BuildCipherZeroOpenSessionRequest(messageTag byte, consoleSessionID uint32) []byte {
	return BuildOpenSessionRequest(messageTag, PrivilegeAdministrator, consoleSessionID,
		AuthAlgorithmRAKPNone, IntegrityAlgorithmNone, ConfidentialityAlgorithmNone)
}

// OpenSessionResponse is the parsed Open Session Response payload.
// Only the fields the deep probe needs are exposed.
type OpenSessionResponse struct {
	MessageTag             byte
	StatusCode             byte
	MaxPrivilegeGranted    byte
	ConsoleSessionID       uint32
	BMCSessionID           uint32
	NegotiatedAuthAlg      byte
	NegotiatedIntegrityAlg byte
	NegotiatedConfAlg      byte
}

// Accepted reports whether the BMC returned a "no errors" status. This
// only confirms the session-open request was accepted at the protocol
// level; it does NOT mean the BMC honored the requested cipher suite.
// Use IsCipherZeroAccepted() at the cipher-zero probe site to confirm
// the BMC actually negotiated the NONE algorithms.
func (r OpenSessionResponse) Accepted() bool { return r.StatusCode == RMCPPlusStatusNoErrors }

// IsCipherZeroAccepted reports whether the BMC accepted the session AND
// actually negotiated the NONE algorithms (auth = 0x00, integrity = 0x00,
// confidentiality = 0x00). A misbehaving BMC can return StatusCode = 0
// while quietly substituting HMAC-SHA1 / AES-CBC — status alone is not a
// Cipher Zero finding. RAKP-existence-oracle callers should keep using
// Accepted() since they intentionally negotiate the HMAC-SHA1 suite.
func (r OpenSessionResponse) IsCipherZeroAccepted() bool {
	return r.StatusCode == RMCPPlusStatusNoErrors &&
		r.NegotiatedAuthAlg == AuthAlgorithmRAKPNone &&
		r.NegotiatedIntegrityAlg == IntegrityAlgorithmNone &&
		r.NegotiatedConfAlg == ConfidentialityAlgorithmNone
}

// ParseOpenSessionResponse reads the payload returned by the BMC for
// an Open Session Request. A truncated response is treated as
// not-accepted (status != 0) rather than an error so the plugin can
// keep moving.
func ParseOpenSessionResponse(resp []byte) (OpenSessionResponse, error) {
	payload, err := ParseIPMI20Payload(resp, PayloadTypeOpenSessionResponse)
	if err != nil {
		return OpenSessionResponse{}, err
	}
	// Per spec the payload is 36 bytes (32-byte request body + 4 added
	// session-ID and status fields). Some BMCs return the abbreviated
	// 12-byte error reply (only through BMCSessionID) when status != 0.
	if len(payload) < 8 {
		return OpenSessionResponse{}, fmt.Errorf("%w: open-session response payload %d bytes",
			ErrTruncatedResponse, len(payload))
	}
	r := OpenSessionResponse{
		MessageTag:          payload[0],
		StatusCode:          payload[1],
		MaxPrivilegeGranted: payload[2],
		ConsoleSessionID:    binary.LittleEndian.Uint32(payload[4:8]),
	}
	if len(payload) >= 12 {
		r.BMCSessionID = binary.LittleEndian.Uint32(payload[8:12])
	}
	if len(payload) >= 36 {
		r.NegotiatedAuthAlg = payload[16]
		r.NegotiatedIntegrityAlg = payload[24]
		r.NegotiatedConfAlg = payload[32]
	}
	return r, nil
}
