// Package plugins provides IKE (Internet Key Exchange) service fingerprinting
package plugins

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type IKEFingerprinter struct{}

func (IKEFingerprinter) Name() string { return "ike" }

func (IKEFingerprinter) DefaultPorts() []int { return []int{500, 4500} }

func (IKEFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	// Create UDP connection
	conn, err := net.DialTimeout("udp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
		return nil, err
	}

	// Build IKEv2 SA_INIT request packet
	ikeRequest := buildIKEv2SAInitRequest()

	// Send the request
	if _, err := conn.Write(ikeRequest); err != nil {
		return nil, err
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	// IKE response must be at least 28 bytes (header size)
	if n < 28 {
		return nil, fmt.Errorf("invalid IKE response size: %d", n)
	}

	// Parse IKE response header
	response := buffer[:n]
	ikeHeader, err := parseIKEHeader(response)
	if err != nil {
		return nil, err
	}

	// Validate it's an IKE response
	if ikeHeader.NextPayload == 0 && ikeHeader.MajorVersion == 0 {
		return nil, fmt.Errorf("invalid IKE header")
	}

	// Parse payloads for additional information
	vendorIDs, proposals := parseIKEPayloads(response[28:n], ikeHeader.NextPayload)

	version := fmt.Sprintf("IKEv%d", ikeHeader.MajorVersion)
	initiatorSPI := hex.EncodeToString(ikeHeader.InitiatorSPI[:])
	responderSPI := hex.EncodeToString(ikeHeader.ResponderSPI[:])
	exchangeType := getExchangeTypeName(ikeHeader.ExchangeType)
	flags := fmt.Sprintf("0x%02x", ikeHeader.Flags)
	messageID := fmt.Sprintf("%d", ikeHeader.MessageID)

	metadata := &protocol.IkeServerInfo{
		Version:      &version,
		InitiatorSpi: &initiatorSPI,
		ResponderSpi: &responderSPI,
		ExchangeType: &exchangeType,
		Flags:        &flags,
		MessageId:    &messageID,
	}

	// Add vendor IDs if any were found
	if len(vendorIDs) > 0 {
		metadata.VendorIds = vendorIDs
	}

	// Add security proposal details if found
	if len(proposals.EncryptionAlgs) > 0 {
		metadata.EncryptionAlgorithms = proposals.EncryptionAlgs
	}
	if len(proposals.HashAlgs) > 0 {
		metadata.HashAlgorithms = proposals.HashAlgs
	}
	if len(proposals.AuthMethods) > 0 {
		metadata.AuthenticationMethods = proposals.AuthMethods
	}
	if len(proposals.DHGroups) > 0 {
		metadata.DhGroups = proposals.DHGroups
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeIke,
		Version:   &version,
		Metadata:  discoverfern.NewServiceMetadataFromIke(metadata),
	}

	return result, nil
}

// IKEHeader represents the IKE message header
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

// SecurityProposals holds parsed security association proposals
type SecurityProposals struct {
	EncryptionAlgs []string
	HashAlgs       []string
	AuthMethods    []string
	DHGroups       []string
}

// parseIKEHeader parses the IKE message header
func parseIKEHeader(data []byte) (*IKEHeader, error) {
	if len(data) < 28 {
		return nil, fmt.Errorf("data too short for IKE header")
	}

	header := &IKEHeader{
		NextPayload:  data[16],
		MajorVersion: (data[17] & 0xF0) >> 4,
		MinorVersion: data[17] & 0x0F,
		ExchangeType: data[18],
		Flags:        data[19],
		MessageID:    binary.BigEndian.Uint32(data[20:24]),
		Length:       binary.BigEndian.Uint32(data[24:28]),
	}

	copy(header.InitiatorSPI[:], data[0:8])
	copy(header.ResponderSPI[:], data[8:16])

	return header, nil
}

// parseIKEPayloads extracts vendor IDs and security proposals from IKE payloads
func parseIKEPayloads(data []byte, nextPayload byte) ([]string, *SecurityProposals) {
	var vendorIDs []string
	proposals := &SecurityProposals{
		EncryptionAlgs: []string{},
		HashAlgs:       []string{},
		AuthMethods:    []string{},
		DHGroups:       []string{},
	}

	currentPayload := nextPayload
	offset := 0

	for offset < len(data) && currentPayload != 0 {
		if offset+4 > len(data) {
			break
		}

		payloadLength := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if payloadLength < 4 || offset+payloadLength > len(data) {
			break
		}

		payloadData := data[offset+4 : offset+payloadLength]

		// Parse vendor ID payloads (type 43)
		if currentPayload == 43 && len(payloadData) > 0 {
			vendorID := string(payloadData)
			// Only add printable vendor IDs
			if isIKEVendorIDPrintable(vendorID) {
				vendorIDs = append(vendorIDs, vendorID)
			} else {
				// Store as hex if not printable
				vendorIDs = append(vendorIDs, hex.EncodeToString(payloadData))
			}
		}

		// Parse Security Association payloads (type 33)
		if currentPayload == 33 && len(payloadData) > 0 {
			parseSAPayload(payloadData, proposals)
		}

		// Move to next payload
		currentPayload = data[offset]
		offset += payloadLength
	}

	return vendorIDs, proposals
}

// parseSAPayload extracts security proposals from SA payload
func parseSAPayload(data []byte, proposals *SecurityProposals) {
	offset := 0
	for offset+8 <= len(data) {
		// Parse proposal
		proposalLength := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if proposalLength < 8 || offset+proposalLength > len(data) {
			break
		}

		numTransforms := int(data[offset+7])
		transformOffset := offset + 8

		// Parse transforms
		for i := 0; i < numTransforms && transformOffset+8 <= len(data); i++ {
			transformLength := int(binary.BigEndian.Uint16(data[transformOffset+2 : transformOffset+4]))
			if transformLength < 8 {
				break
			}

			transformType := data[transformOffset+4]
			transformID := binary.BigEndian.Uint16(data[transformOffset+6 : transformOffset+8])

			switch transformType {
			case 1: // Encryption Algorithm
				proposals.EncryptionAlgs = appendUnique(proposals.EncryptionAlgs, getEncryptionAlgorithmName(transformID))
			case 2: // PRF (Pseudo-random Function)
				proposals.HashAlgs = appendUnique(proposals.HashAlgs, getPRFName(transformID))
			case 3: // Integrity Algorithm
				proposals.HashAlgs = appendUnique(proposals.HashAlgs, getIntegrityAlgorithmName(transformID))
			case 4: // Diffie-Hellman Group
				proposals.DHGroups = appendUnique(proposals.DHGroups, getDHGroupName(transformID))
			}

			transformOffset += transformLength
		}

		offset += proposalLength
	}
}

// Helper function to append unique strings
func appendUnique(slice []string, item string) []string {
	for _, existing := range slice {
		if existing == item {
			return slice
		}
	}
	return append(slice, item)
}

// isIKEVendorIDPrintable checks if a string contains only printable ASCII characters
func isIKEVendorIDPrintable(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}

// buildIKEv2SAInitRequest creates an IKEv2 SA_INIT request packet
func buildIKEv2SAInitRequest() []byte {
	// IKE header (28 bytes)
	packet := make([]byte, 28)

	// Initiator SPI (8 bytes) - random
	initiatorSPI := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	copy(packet[0:8], initiatorSPI)

	// Responder SPI (8 bytes) - zeros for initial request
	// Already zeros from make()

	// Next Payload: SA (33)
	packet[16] = 33

	// Version: 2.0
	packet[17] = 0x20 // Major: 2, Minor: 0

	// Exchange Type: IKE_SA_INIT (34)
	packet[18] = 34

	// Flags: Initiator
	packet[19] = 0x08

	// Message ID: 0
	// Already zeros

	// Length: 28 (just header for simple detection)
	binary.BigEndian.PutUint32(packet[24:28], 28)

	return packet
}

// getExchangeTypeName returns the human-readable name for an exchange type
func getExchangeTypeName(exchangeType byte) string {
	switch exchangeType {
	case 34:
		return "IKE_SA_INIT"
	case 35:
		return "IKE_AUTH"
	case 36:
		return "CREATE_CHILD_SA"
	case 37:
		return "INFORMATIONAL"
	default:
		return fmt.Sprintf("UNKNOWN_%d", exchangeType)
	}
}

// getEncryptionAlgorithmName returns the name for an encryption algorithm ID
func getEncryptionAlgorithmName(id uint16) string {
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

// getPRFName returns the name for a PRF algorithm ID
func getPRFName(id uint16) string {
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

// getIntegrityAlgorithmName returns the name for an integrity algorithm ID
func getIntegrityAlgorithmName(id uint16) string {
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

// getDHGroupName returns the name for a Diffie-Hellman group ID
func getDHGroupName(id uint16) string {
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
