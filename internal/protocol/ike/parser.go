// Package ike provides shared IKE (Internet Key Exchange) protocol parsing and
// packet-building utilities used by both the discover and enumerate modules.
package ike

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// IKEHeader represents the parsed 28-byte IKE message header.
type IKEHeader struct {
	InitiatorSPI [8]byte
	ResponderSPI [8]byte
	NextPayload  byte
	MajorVersion byte
	MinorVersion byte
	ExchangeType byte
	Flags        byte
	MessageID    uint32
	Length       uint32
}

// SecurityProposals holds parsed IKE security association proposals.
type SecurityProposals struct {
	EncryptionAlgs []string
	HashAlgs       []string
	AuthMethods    []string
	DHGroups       []string
}

// ParseIKEHeader parses the 28-byte IKE message header.
func ParseIKEHeader(data []byte) (*IKEHeader, error) {
	if len(data) < 28 {
		return nil, fmt.Errorf("data too short for IKE header: %d bytes", len(data))
	}
	h := &IKEHeader{
		NextPayload:  data[16],
		MajorVersion: (data[17] & 0xF0) >> 4,
		MinorVersion: data[17] & 0x0F,
		ExchangeType: data[18],
		Flags:        data[19],
		MessageID:    binary.BigEndian.Uint32(data[20:24]),
		Length:       binary.BigEndian.Uint32(data[24:28]),
	}
	copy(h.InitiatorSPI[:], data[0:8])
	copy(h.ResponderSPI[:], data[8:16])
	return h, nil
}

// ParseIKEPayloads extracts vendor IDs (hex-encoded) and SA proposals from the
// payload section of an IKE message. nextPayload is taken from the IKE header.
func ParseIKEPayloads(data []byte, nextPayload byte) ([]string, *SecurityProposals) {
	var vendorIDs []string
	proposals := &SecurityProposals{}
	current := nextPayload
	offset := 0
	for offset < len(data) && current != 0 {
		if offset+4 > len(data) {
			break
		}
		payloadLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if payloadLen < 4 || offset+payloadLen > len(data) {
			break
		}
		payload := data[offset+4 : offset+payloadLen]
		switch current {
		case 43: // Vendor ID — always store as lowercase hex for consistent matching
			if len(payload) > 0 {
				vendorIDs = append(vendorIDs, hex.EncodeToString(payload))
			}
		case 33: // Security Association (IKEv2)
			ParseSAPayload(payload, proposals)
		}
		current = data[offset]
		offset += payloadLen
	}
	return vendorIDs, proposals
}

// ParseSAPayload extracts transform attributes from an IKEv2 SA payload,
// correctly skipping any per-proposal SPI bytes before the transform list.
func ParseSAPayload(data []byte, proposals *SecurityProposals) {
	offset := 0
	for offset+8 <= len(data) {
		proposalLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if proposalLen < 8 || offset+proposalLen > len(data) {
			break
		}
		spiSize := int(data[offset+6])
		numTransforms := int(data[offset+7])
		txOffset := offset + 8 + spiSize
		if txOffset > offset+proposalLen {
			offset += proposalLen
			continue
		}
		for i := 0; i < numTransforms && txOffset+8 <= len(data); i++ {
			txLen := int(binary.BigEndian.Uint16(data[txOffset+2 : txOffset+4]))
			if txLen < 8 {
				break
			}
			txType := data[txOffset+4]
			txID := binary.BigEndian.Uint16(data[txOffset+6 : txOffset+8])
			switch txType {
			case 1:
				proposals.EncryptionAlgs = AppendUnique(proposals.EncryptionAlgs, GetEncryptionAlgorithmName(txID))
			case 2:
				proposals.HashAlgs = AppendUnique(proposals.HashAlgs, GetPRFName(txID))
			case 3:
				proposals.HashAlgs = AppendUnique(proposals.HashAlgs, GetIntegrityAlgorithmName(txID))
			case 4:
				proposals.DHGroups = AppendUnique(proposals.DHGroups, GetDHGroupName(txID))
			}
			txOffset += txLen
		}
		offset += proposalLen
	}
}

// BuildIKEv2SAInitRequest creates a well-formed IKEv2 IKE_SA_INIT request
// with SA, KE, and Nonce payloads. The SA proposes 3DES-CBC + HMAC-SHA1 +
// HMAC-SHA1-96 + MODP-1024 — a widely supported set that does not require
// key-length attributes. The KE carries 128 zero bytes (valid MODP-1024 size)
// and the Nonce carries 32 bytes. Together these satisfy the RFC 7296 §1.2
// minimum and will elicit an IKE_SA_INIT response (or a NOTIFY error) from
// any conformant responder.
//
// Use this for the standard IKE port (UDP 500).
func BuildIKEv2SAInitRequest() []byte {
	// --- Transforms (8 bytes each, no variable-length attributes) ---
	// Last/More byte: 0x03 = more transforms, 0x00 = last transform.
	transforms := []byte{
		0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x03, // Enc:  3DES-CBC      (type 1, id 3)
		0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x02, // PRF:  HMAC-SHA1     (type 2, id 2)
		0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x02, // Auth: HMAC-SHA1-96  (type 3, id 2)
		0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x02, // DH:   MODP-1024     (type 4, id 2)
	}

	// --- Proposal (8-byte header + transforms) ---
	proposalLen := 8 + len(transforms)
	proposal := make([]byte, proposalLen)
	proposal[0] = 0x00 // last proposal
	binary.BigEndian.PutUint16(proposal[2:4], uint16(proposalLen))
	proposal[4] = 0x01 // proposal #1
	proposal[5] = 0x01 // protocol: IKE
	proposal[6] = 0x00 // SPI size: 0
	proposal[7] = 0x04 // # transforms: 4
	copy(proposal[8:], transforms)

	// --- SA payload (generic header + proposal) ---
	saLen := 4 + len(proposal)
	sa := make([]byte, saLen)
	sa[0] = 34 // next payload: KE
	binary.BigEndian.PutUint16(sa[2:4], uint16(saLen))
	copy(sa[4:], proposal)

	// --- KE payload: MODP-1024 requires 128 bytes of key material ---
	keBody := make([]byte, 4+128)              // DH-group (2) + reserved (2) + 128 zeros
	binary.BigEndian.PutUint16(keBody[0:2], 2) // DH Group: MODP-1024
	keLen := 4 + len(keBody)
	ke := make([]byte, keLen)
	ke[0] = 40 // next payload: Nonce
	binary.BigEndian.PutUint16(ke[2:4], uint16(keLen))
	copy(ke[4:], keBody)

	// --- Nonce payload: 32 bytes ---
	nonceData := make([]byte, 32)
	for i := range nonceData {
		nonceData[i] = byte(i + 1)
	}
	nonceLen := 4 + len(nonceData)
	nonce := make([]byte, nonceLen)
	nonce[0] = 0x00 // next payload: none
	binary.BigEndian.PutUint16(nonce[2:4], uint16(nonceLen))
	copy(nonce[4:], nonceData)

	// --- Assemble body and IKE header ---
	body := append(sa, ke...)
	body = append(body, nonce...)

	header := make([]byte, 28)
	copy(header[0:8], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}) // initiator SPI
	header[16] = 33                                                           // next payload: SA
	header[17] = 0x20                                                         // version: IKEv2
	header[18] = 34                                                           // exchange type: IKE_SA_INIT
	header[19] = 0x08                                                         // flags: initiator
	binary.BigEndian.PutUint32(header[24:28], uint32(28+len(body)))
	return append(header, body...)
}

// BuildNATTIKEv1AMRequest wraps an IKEv1 Aggressive Mode packet with the
// 4-byte Non-ESP marker required by RFC 3948 §2.3 for UDP port 4500.
// The caller supplies the raw IKEv1 AM probe bytes.
func BuildNATTIKEv1AMRequest(ikev1AM []byte) []byte {
	framed := make([]byte, 4+len(ikev1AM))
	binary.BigEndian.PutUint32(framed[0:4], 0)
	copy(framed[4:], ikev1AM)
	return framed
}

// BuildNATTIKEv2SAInitRequest creates an IKEv2 IKE_SA_INIT request framed for
// UDP port 4500 per RFC 3948 §2.3: a 4-byte Non-ESP marker (0x00000000) is
// prepended so the receiver can distinguish IKE traffic from ESP packets.
func BuildNATTIKEv2SAInitRequest() []byte {
	ike := BuildIKEv2SAInitRequest()
	framed := make([]byte, 4+len(ike))
	// Non-ESP marker: four zero bytes (RFC 3948 §2.3)
	binary.BigEndian.PutUint32(framed[0:4], 0)
	copy(framed[4:], ike)
	return framed
}

// GetExchangeTypeName returns the human-readable name for an IKE exchange type.
func GetExchangeTypeName(t byte) string {
	switch t {
	case 34:
		return "IKE_SA_INIT"
	case 35:
		return "IKE_AUTH"
	case 36:
		return "CREATE_CHILD_SA"
	case 37:
		return "INFORMATIONAL"
	default:
		return fmt.Sprintf("UNKNOWN_%d", t)
	}
}

// GetEncryptionAlgorithmName returns the IANA name for an IKEv2 encryption
// transform ID (RFC 7296 / IANA "IKEv2 Transform Type 1" registry).
func GetEncryptionAlgorithmName(id uint16) string {
	switch id {
	case 1:
		return "DES-IV64"
	case 2:
		return "DES"
	case 3:
		return "3DES-CBC"
	case 5:
		return "IDEA-CBC"
	case 6:
		return "CAST-CBC"
	case 7:
		return "Blowfish-CBC"
	case 11:
		return "NULL"
	case 12:
		return "AES-CBC"
	case 13:
		return "AES-CTR"
	case 18:
		return "AES-GCM-8"
	case 19:
		return "AES-GCM-12"
	case 20:
		return "AES-GCM-16"
	case 23:
		return "Camellia-CBC"
	case 28:
		return "ChaCha20-Poly1305"
	default:
		return fmt.Sprintf("ENC_%d", id)
	}
}

// GetPRFName returns the IANA name for an IKEv2 PRF transform ID
// (RFC 7296 / IANA "IKEv2 Transform Type 2" registry).
func GetPRFName(id uint16) string {
	switch id {
	case 1:
		return "PRF-HMAC-MD5"
	case 2:
		return "PRF-HMAC-SHA1"
	case 3:
		return "PRF-HMAC-TIGER"
	case 4:
		return "PRF-AES128-XCBC"
	case 5:
		return "PRF-HMAC-SHA256"
	case 6:
		return "PRF-HMAC-SHA384"
	case 7:
		return "PRF-HMAC-SHA512"
	case 8:
		return "PRF-AES128-CMAC"
	default:
		return fmt.Sprintf("PRF_%d", id)
	}
}

// GetIntegrityAlgorithmName returns the IANA name for an IKEv2 integrity
// transform ID (RFC 7296 / IANA "IKEv2 Transform Type 3" registry).
func GetIntegrityAlgorithmName(id uint16) string {
	switch id {
	case 0:
		return "NONE"
	case 1:
		return "HMAC-MD5-96"
	case 2:
		return "HMAC-SHA1-96"
	case 3:
		return "DES-MAC"
	case 4:
		return "KPDK-MD5"
	case 5:
		return "AES-XCBC-96"
	case 6:
		return "HMAC-MD5-128"
	case 7:
		return "HMAC-SHA1-160"
	case 8:
		return "AES-CMAC-96"
	case 9:
		return "AES-128-GMAC"
	case 10:
		return "AES-192-GMAC"
	case 11:
		return "AES-256-GMAC"
	case 12:
		return "HMAC-SHA256-128"
	case 13:
		return "HMAC-SHA384-192"
	case 14:
		return "HMAC-SHA512-256"
	default:
		return fmt.Sprintf("AUTH_%d", id)
	}
}

// GetDHGroupName returns the IANA name for an IKEv2 Diffie-Hellman group ID
// (RFC 7296 / IANA "IKEv2 Transform Type 4" registry).
func GetDHGroupName(id uint16) string {
	switch id {
	case 1:
		return "MODP-768"
	case 2:
		return "MODP-1024"
	case 5:
		return "MODP-1536"
	case 14:
		return "MODP-2048"
	case 15:
		return "MODP-3072"
	case 16:
		return "MODP-4096"
	case 17:
		return "MODP-6144"
	case 18:
		return "MODP-8192"
	case 19:
		return "ECP-256"
	case 20:
		return "ECP-384"
	case 21:
		return "ECP-521"
	case 22:
		return "MODP-1024-160"
	case 23:
		return "MODP-2048-224"
	case 24:
		return "MODP-2048-256"
	case 25:
		return "ECP-192"
	case 26:
		return "ECP-224"
	case 27:
		return "ECP-224-BP"
	case 28:
		return "ECP-256-BP"
	case 29:
		return "ECP-384-BP"
	case 30:
		return "ECP-512-BP"
	case 31:
		return "Curve25519"
	case 32:
		return "Curve448"
	default:
		return fmt.Sprintf("DH_%d", id)
	}
}

// ParseIKEv1SAResponse walks the payload chain of an IKEv1 response packet and
// extracts the encryption algorithm, hash algorithm, and DH group from the SA
// payload. It is tolerant of missing or malformed payloads and returns whatever
// it can parse. On a successful IKEv1 AM exchange (type 4) the server includes
// the selected proposal; on INFORMATIONAL (type 5) there is no SA, so the
// result will be empty — that is handled gracefully.
func ParseIKEv1SAResponse(data []byte) *SecurityProposals {
	proposals := &SecurityProposals{}
	if len(data) < 28 {
		return proposals
	}
	nextPayload := data[16]
	offset := 28
	for offset+4 <= len(data) && nextPayload != 0 {
		payloadNext := data[offset]
		payloadLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if payloadLen < 4 || offset+payloadLen > len(data) {
			break
		}
		if nextPayload == 1 { // SA payload
			// SA body: skip generic header (4), DOI (4), Situation (4)
			if payloadLen > 12 {
				parseIKEv1Proposals(data[offset+12:offset+payloadLen], proposals)
			}
			break
		}
		nextPayload = payloadNext
		offset += payloadLen
	}
	return proposals
}

func parseIKEv1Proposals(data []byte, proposals *SecurityProposals) {
	offset := 0
	for offset+8 <= len(data) {
		propLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if propLen < 8 || offset+propLen > len(data) {
			break
		}
		spiSize := int(data[offset+6])
		numTransforms := int(data[offset+7])
		txOffset := offset + 8 + spiSize
		for i := 0; i < numTransforms && txOffset+8 <= offset+propLen; i++ {
			txLen := int(binary.BigEndian.Uint16(data[txOffset+2 : txOffset+4]))
			if txLen < 8 {
				break
			}
			transformEnd := txOffset + txLen
			// txLen is untrusted network input; ensure it cannot overrun the
			// proposal bounds before slicing transform attributes.
			if transformEnd > offset+propLen || transformEnd > len(data) {
				break
			}
			parseIKEv1TransformAttrs(data[txOffset+8:transformEnd], proposals)
			txOffset += txLen
		}
		if data[offset] == 0 {
			break
		}
		offset += propLen
	}
}

func parseIKEv1TransformAttrs(data []byte, proposals *SecurityProposals) {
	offset := 0
	for offset+4 <= len(data) {
		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		attrVal := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		if attrType&0x8000 != 0 {
			// TV format (type-value, 4 bytes total)
			switch attrType & 0x7FFF {
			case 1: // Encryption Algorithm
				proposals.EncryptionAlgs = AppendUnique(proposals.EncryptionAlgs, GetIKEv1EncryptionName(attrVal))
			case 2: // Hash Algorithm
				proposals.HashAlgs = AppendUnique(proposals.HashAlgs, GetIKEv1HashName(attrVal))
			case 3: // Authentication Method
				proposals.AuthMethods = AppendUnique(proposals.AuthMethods, GetIKEv1AuthMethodName(attrVal))
			case 4: // Group Description — same numeric IDs as IKEv2
				proposals.DHGroups = AppendUnique(proposals.DHGroups, GetDHGroupName(attrVal))
			}
			offset += 4
		} else {
			// TLV format — skip value bytes
			offset += 4 + int(attrVal)
		}
	}
}

// GetIKEv1EncryptionName returns the name for an IKEv1 encryption algorithm ID
// (RFC 2409 / IANA "ISAKMP Encryption Algorithm" registry).
func GetIKEv1EncryptionName(id uint16) string {
	switch id {
	case 1:
		return "DES-CBC"
	case 3:
		return "Blowfish-CBC"
	case 5:
		return "3DES-CBC"
	case 6:
		return "CAST-CBC"
	case 7:
		return "AES-CBC"
	case 8:
		return "Camellia-CBC"
	default:
		return fmt.Sprintf("ENC_%d", id)
	}
}

// GetIKEv1HashName returns the name for an IKEv1 hash algorithm ID
// (RFC 2409 / IANA "ISAKMP Hash Algorithm" registry).
func GetIKEv1HashName(id uint16) string {
	switch id {
	case 1:
		return "MD5"
	case 2:
		return "SHA1"
	case 4:
		return "SHA256"
	case 5:
		return "SHA384"
	case 6:
		return "SHA512"
	default:
		return fmt.Sprintf("HASH_%d", id)
	}
}

// GetIKEv1AuthMethodName returns the name for an IKEv1 authentication method ID
// (RFC 2409 / IANA "ISAKMP Authentication Method" registry).
func GetIKEv1AuthMethodName(id uint16) string {
	switch id {
	case 1:
		return "PSK"
	case 2:
		return "DSS_SIGNATURE"
	case 3:
		return "RSA_SIGNATURE"
	case 9:
		return "ECDSA_SHA256_P256"
	case 10:
		return "ECDSA_SHA384_P384"
	case 11:
		return "ECDSA_SHA512_P521"
	default:
		return fmt.Sprintf("AUTH_METHOD_%d", id)
	}
}

// ParseIKEv1NotificationType returns the Notify Message Type from the first
// Notification payload (type 11) in an IKEv1 Informational message, or 0 if
// no notification payload is found or the packet is too short to parse.
//
// IKEv1 Notification payload layout (RFC 2408 §3.14):
//
//	generic header (4): next, reserved, length
//	DOI             (4)
//	Protocol-ID     (1)
//	SPI-size        (1)
//	Notify type     (2)
func ParseIKEv1NotificationType(data []byte) uint16 {
	if len(data) < 28 {
		return 0
	}
	nextPayload := data[16]
	offset := 28
	for offset+4 <= len(data) && nextPayload != 0 {
		payloadNext := data[offset]
		payloadLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if payloadLen < 4 || offset+payloadLen > len(data) {
			break
		}
		if nextPayload == 11 { // Notification payload
			// Need at least 12 bytes: generic header (4) + DOI (4) + Protocol-ID (1) + SPI-size (1) + Notify type (2)
			if payloadLen >= 12 {
				return binary.BigEndian.Uint16(data[offset+10 : offset+12])
			}
		}
		nextPayload = payloadNext
		offset += payloadLen
	}
	return 0
}

// AppendUnique appends item to slice only if it is not already present.
func AppendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
