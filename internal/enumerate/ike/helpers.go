package ike

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// --- UDP Probe ---
// probeUDP sends a UDP packet to addr and returns the response.
func probeUDP(ctx context.Context, addr string, packet []byte) ([]byte, error) {
	timeout := 5 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
	} else {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}
	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// --- IKEv2 Packet Builder ---
// buildIKEv2SAInitRequest creates a minimal IKEv2 IKE_SA_INIT request.
func buildIKEv2SAInitRequest() []byte {
	packet := make([]byte, 28)
	copy(packet[0:8], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}) // initiator SPI
	packet[16] = 33                                                           // next payload: SA
	packet[17] = 0x20                                                         // version: IKEv2
	packet[18] = 34                                                           // exchange type: IKE_SA_INIT
	packet[19] = 0x08                                                         // flags: initiator
	binary.BigEndian.PutUint32(packet[24:28], 28)
	return packet
}

// --- IKEv1 Aggressive Mode Packet Builder ---
// buildIKEv1AggressiveModeProbe creates an IKEv1 Aggressive Mode probe packet.
// It proposes DES-CBC + MD5 + PSK + MODP-768 — the weakest common set — to
// maximize the chance that a configured server will accept and respond.
func buildIKEv1AggressiveModeProbe() []byte {
	// Transform: DES-CBC / MD5 / PSK / DH-Group1 (MODP-768)
	// Attributes use TV (Type-Value) format: MSB of type byte = 1
	transform := []byte{
		0x00, 0x00, 0x00, 0x20, // next=0(last), reserved, len=32
		0x01, 0x01, 0x00, 0x00, // transform#=1, ID=KEY_IKE, reserved2
		0x80, 0x01, 0x00, 0x01, // Encryption: DES-CBC
		0x80, 0x02, 0x00, 0x01, // Hash: MD5
		0x80, 0x03, 0x00, 0x01, // Auth: PSK
		0x80, 0x04, 0x00, 0x01, // DH Group: MODP-768
		0x80, 0x0b, 0x00, 0x01, // Life Type: seconds
		0x80, 0x0c, 0x70, 0x80, // Life Duration: 28800s (TV format)
	}
	// Proposal: protocol=ISAKMP, SPI-size=0, 1 transform
	proposal := make([]byte, 8+len(transform))
	proposal[4] = 0x01 // proposal #1
	proposal[5] = 0x01 // protocol: ISAKMP
	proposal[6] = 0x00 // SPI size: 0
	proposal[7] = 0x01 // # transforms: 1
	binary.BigEndian.PutUint16(proposal[2:4], uint16(len(proposal)))
	copy(proposal[8:], transform)
	// SA payload: next=KE(4), DOI=IPSEC, Situation=SIT_IDENTITY_ONLY
	saPayload := make([]byte, 4+4+4+len(proposal))
	saPayload[0] = 0x04 // next: KE
	binary.BigEndian.PutUint16(saPayload[2:4], uint16(len(saPayload)))
	binary.BigEndian.PutUint32(saPayload[4:8], 1)  // DOI: IPSEC
	binary.BigEndian.PutUint32(saPayload[8:12], 1) // Situation: SIT_IDENTITY_ONLY
	copy(saPayload[12:], proposal)
	// KE payload: MODP-768 = 96 bytes of zeros; next=Nonce(10)
	kePayload := make([]byte, 4+96)
	kePayload[0] = 0x0a // next: Nonce
	binary.BigEndian.PutUint16(kePayload[2:4], uint16(len(kePayload)))
	// Nonce payload: 16 zero bytes; next=ID(5)
	noncePayload := make([]byte, 4+16)
	noncePayload[0] = 0x05 // next: ID
	binary.BigEndian.PutUint16(noncePayload[2:4], uint16(len(noncePayload)))
	// ID payload: ID_IPV4_ADDR for 192.168.0.1; next=0(none)
	idPayload := []byte{
		0x00, 0x00, 0x00, 0x0c, // next=0, reserved, len=12
		0x01, 0x00, 0x00, 0x00, // ID_IPV4_ADDR, protocol=0, port=0
		0xc0, 0xa8, 0x00, 0x01, // 192.168.0.1
	}
	body := append(saPayload, kePayload...)
	body = append(body, noncePayload...)
	body = append(body, idPayload...)
	// IKE header
	header := make([]byte, 28)
	copy(header[0:8], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}) // initiator SPI
	header[16] = 0x01                                                         // next payload: SA
	header[17] = 0x10                                                         // version: IKEv1
	header[18] = 0x04                                                         // exchange type: Aggressive Mode
	binary.BigEndian.PutUint32(header[24:28], uint32(28+len(body)))
	return append(header, body...)
}

// --- IKE Header Parsing (shared with discover plugin) ---
// IKEHeader represents the parsed IKE message header.
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

// parseIKEHeader parses the 28-byte IKE message header.
func parseIKEHeader(data []byte) (*IKEHeader, error) {
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

// isIKEv1AggressiveResponse checks if a raw IKE response is an IKEv1 Aggressive Mode reply.
func isIKEv1AggressiveResponse(data []byte) (aggressiveMode bool, ikev1Supported bool) {
	if len(data) < 28 {
		return false, false
	}
	majorVersion := (data[17] & 0xF0) >> 4
	exchangeType := data[18]
	if majorVersion == 1 {
		ikev1Supported = true
		aggressiveMode = exchangeType == 4
	}
	return aggressiveMode, ikev1Supported
}

// --- Payload Parsing (shared with discover plugin) ---
// SecurityProposals holds parsed IKE security association proposals.
type SecurityProposals struct {
	EncryptionAlgs []string
	HashAlgs       []string
	AuthMethods    []string
	DHGroups       []string
}

// parseIKEPayloads extracts vendor IDs and SA proposals from the payload section.
func parseIKEPayloads(data []byte, nextPayload byte) ([]string, *SecurityProposals) {
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
		case 43: // Vendor ID
			if len(payload) > 0 {
				h := hex.EncodeToString(payload)
				if isAllPrintable(string(payload)) {
					vendorIDs = append(vendorIDs, string(payload))
				} else {
					vendorIDs = append(vendorIDs, h)
				}
			}
		case 33: // Security Association (IKEv2)
			parseSAPayload(payload, proposals)
		}
		current = data[offset]
		offset += payloadLen
	}
	return vendorIDs, proposals
}
func parseSAPayload(data []byte, proposals *SecurityProposals) {
	offset := 0
	for offset+8 <= len(data) {
		proposalLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if proposalLen < 8 || offset+proposalLen > len(data) {
			break
		}
		numTransforms := int(data[offset+7])
		txOffset := offset + 8
		for i := 0; i < numTransforms && txOffset+8 <= len(data); i++ {
			txLen := int(binary.BigEndian.Uint16(data[txOffset+2 : txOffset+4]))
			if txLen < 8 {
				break
			}
			txType := data[txOffset+4]
			txID := binary.BigEndian.Uint16(data[txOffset+6 : txOffset+8])
			switch txType {
			case 1:
				proposals.EncryptionAlgs = appendUnique(proposals.EncryptionAlgs, getEncryptionAlgorithmName(txID))
			case 2:
				proposals.HashAlgs = appendUnique(proposals.HashAlgs, getPRFName(txID))
			case 3:
				proposals.HashAlgs = appendUnique(proposals.HashAlgs, getIntegrityAlgorithmName(txID))
			case 4:
				proposals.DHGroups = appendUnique(proposals.DHGroups, getDHGroupName(txID))
			}
			txOffset += txLen
		}
		offset += proposalLen
	}
}

// --- Security Assessment Helpers ---
// detectWeakAlgorithms returns a list of weak algorithm names found in the SA proposals.
func detectWeakAlgorithms(encAlgs, hashAlgs, dhGroups []string) []string {
	var weak []string
	for _, alg := range encAlgs {
		for _, w := range weakEncryptionAlgorithms {
			if alg == w {
				weak = appendUnique(weak, alg)
			}
		}
	}
	for _, alg := range hashAlgs {
		for _, w := range weakHashAlgorithms {
			if alg == w {
				weak = appendUnique(weak, alg)
			}
		}
	}
	for _, g := range dhGroups {
		for _, w := range weakDHGroups {
			if g == w {
				weak = appendUnique(weak, g)
			}
		}
	}
	return weak
}

// checkDPDSupport returns true if any vendor ID matches the Dead Peer Detection magic.
func checkDPDSupport(vendorIDs []string) bool {
	for _, vid := range vendorIDs {
		lower := strings.ToLower(vid)
		if strings.HasPrefix(lower, dpdVendorIDPrefix) {
			return true
		}
	}
	return false
}

// extractVendorIdentification returns a human-readable vendor name if any vendor ID is recognized.
func extractVendorIdentification(vendorIDs []string) *string {
	for _, vid := range vendorIDs {
		lower := strings.ToLower(vid)
		if name, ok := knownVendorIDs[lower]; ok {
			return &name
		}
	}
	return nil
}

// --- Algorithm Name Maps (from RFC 7296 / IANA IKEv2 registries) ---
func getExchangeTypeName(t byte) string {
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
func getEncryptionAlgorithmName(id uint16) string {
	switch id {
	case 1:
		return "DES-CBC"
	case 5:
		return "3DES-CBC"
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
	case 28:
		return "ChaCha20-Poly1305"
	default:
		return fmt.Sprintf("ENC_%d", id)
	}
}
func getPRFName(id uint16) string {
	switch id {
	case 1:
		return "PRF-HMAC-MD5"
	case 2:
		return "PRF-HMAC-SHA1"
	case 5:
		return "PRF-HMAC-SHA256"
	case 6:
		return "PRF-HMAC-SHA384"
	case 7:
		return "PRF-HMAC-SHA512"
	default:
		return fmt.Sprintf("PRF_%d", id)
	}
}
func getIntegrityAlgorithmName(id uint16) string {
	switch id {
	case 0:
		return "NONE"
	case 1:
		return "HMAC-MD5-96"
	case 2:
		return "HMAC-SHA1-96"
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
	case 19:
		return "ECP-256"
	case 20:
		return "ECP-384"
	case 21:
		return "ECP-521"
	case 31:
		return "Curve25519"
	case 32:
		return "Curve448"
	default:
		return fmt.Sprintf("DH_%d", id)
	}
}

// --- Utility ---
func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
func isAllPrintable(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}
