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

// BuildIKEv2SAInitRequest creates a minimal IKEv2 IKE_SA_INIT request packet.
func BuildIKEv2SAInitRequest() []byte {
	packet := make([]byte, 28)
	copy(packet[0:8], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}) // initiator SPI
	packet[16] = 33                                                           // next payload: SA
	packet[17] = 0x20                                                         // version: IKEv2
	packet[18] = 34                                                           // exchange type: IKE_SA_INIT
	packet[19] = 0x08                                                         // flags: initiator
	binary.BigEndian.PutUint32(packet[24:28], 28)
	return packet
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
		return "DES-CBC"
	case 2:
		return "IDEA-CBC"
	case 3:
		return "Blowfish-CBC"
	case 5:
		return "3DES-CBC"
	case 7:
		return "CAST-CBC"
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

// AppendUnique appends item to slice only if it is not already present.
func AppendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
