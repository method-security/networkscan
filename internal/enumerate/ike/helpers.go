package ike

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	ikeprotocol "github.com/Method-Security/networkscan/internal/protocol/ike"
)

// isPlausibleIKEPacket performs a sanity check on raw data before trusting IKE header fields.
// It validates that the length field in the IKE header matches the actual data length,
// rejecting non-IKE packets that happen to have coincidental byte values.
func isPlausibleIKEPacket(data []byte) bool {
	if len(data) < 28 {
		return false
	}
	declaredLen := binary.BigEndian.Uint32(data[24:28])
	// The declared length must match actual data length exactly (±0 for UDP).
	// Allow declared <= actual to handle truncation by intermediate devices.
	return declaredLen >= 28 && int(declaredLen) <= len(data)
}

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
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
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

// --- IKEv1 Aggressive Mode Packet Builder ---
// buildIKEv1AggressiveModeProbe creates an IKEv1 Aggressive Mode probe with
// MODP-1024 KE. Covers SHA-1 and SHA-256 hash variants.
func buildIKEv1AggressiveModeProbe() []byte {
	return buildIKEv1AMProbeForDH(0x02, 128) // MODP-1024
}

// buildIKEv1AMProbeModp2048 creates an IKEv1 Aggressive Mode probe with
// MODP-2048 KE for servers that require stronger DH groups.
func buildIKEv1AMProbeModp2048() []byte {
	return buildIKEv1AMProbeForDH(0x0e, 256) // MODP-2048
}

// buildIKEv1AMProbeForDH builds an IKEv1 Aggressive Mode probe packet with the
// specified DH group. It proposes six transforms (3DES-CBC, AES-128, AES-256
// each paired with SHA-1 and SHA-256) all with PSK auth.
func buildIKEv1AMProbeForDH(dhGroupID uint16, keSize int) []byte {
	dhHi := byte(dhGroupID >> 8)
	dhLo := byte(dhGroupID & 0xFF)
	// Six transforms covering SHA-1 and SHA-256 with the specified DH group.
	// Attributes use TV (Type-Value) format: MSB of type byte = 1.
	// Last/More byte: 0x03 = more transforms, 0x00 = last transform.
	transforms := []byte{
		// Transform 1: 3DES-CBC + SHA1 + PSK + DH
		0x03, 0x00, 0x00, 0x20, 0x01, 0x01, 0x00, 0x00,
		0x80, 0x01, 0x00, 0x05, // Encryption: 3DES-CBC
		0x80, 0x02, 0x00, 0x02, // Hash: SHA1
		0x80, 0x03, 0x00, 0x01, // Auth: PSK
		0x80, 0x04, dhHi, dhLo, // DH Group
		0x80, 0x0b, 0x00, 0x01, // Life Type: seconds
		0x80, 0x0c, 0x70, 0x80, // Life Duration: 28800s

		// Transform 2: AES-128-CBC + SHA1 + PSK + DH
		0x03, 0x00, 0x00, 0x24, 0x02, 0x01, 0x00, 0x00,
		0x80, 0x01, 0x00, 0x07, // Encryption: AES-CBC
		0x80, 0x0e, 0x00, 0x80, // Key Length: 128 bits
		0x80, 0x02, 0x00, 0x02, // Hash: SHA1
		0x80, 0x03, 0x00, 0x01, // Auth: PSK
		0x80, 0x04, dhHi, dhLo, // DH Group
		0x80, 0x0b, 0x00, 0x01, // Life Type: seconds
		0x80, 0x0c, 0x70, 0x80, // Life Duration: 28800s

		// Transform 3: AES-256-CBC + SHA1 + PSK + DH
		0x03, 0x00, 0x00, 0x24, 0x03, 0x01, 0x00, 0x00,
		0x80, 0x01, 0x00, 0x07, // Encryption: AES-CBC
		0x80, 0x0e, 0x01, 0x00, // Key Length: 256 bits
		0x80, 0x02, 0x00, 0x02, // Hash: SHA1
		0x80, 0x03, 0x00, 0x01, // Auth: PSK
		0x80, 0x04, dhHi, dhLo, // DH Group
		0x80, 0x0b, 0x00, 0x01, // Life Type: seconds
		0x80, 0x0c, 0x70, 0x80, // Life Duration: 28800s

		// Transform 4: 3DES-CBC + SHA256 + PSK + DH
		0x03, 0x00, 0x00, 0x20, 0x04, 0x01, 0x00, 0x00,
		0x80, 0x01, 0x00, 0x05, // Encryption: 3DES-CBC
		0x80, 0x02, 0x00, 0x04, // Hash: SHA256
		0x80, 0x03, 0x00, 0x01, // Auth: PSK
		0x80, 0x04, dhHi, dhLo, // DH Group
		0x80, 0x0b, 0x00, 0x01, // Life Type: seconds
		0x80, 0x0c, 0x70, 0x80, // Life Duration: 28800s

		// Transform 5: AES-128-CBC + SHA256 + PSK + DH
		0x03, 0x00, 0x00, 0x24, 0x05, 0x01, 0x00, 0x00,
		0x80, 0x01, 0x00, 0x07, // Encryption: AES-CBC
		0x80, 0x0e, 0x00, 0x80, // Key Length: 128 bits
		0x80, 0x02, 0x00, 0x04, // Hash: SHA256
		0x80, 0x03, 0x00, 0x01, // Auth: PSK
		0x80, 0x04, dhHi, dhLo, // DH Group
		0x80, 0x0b, 0x00, 0x01, // Life Type: seconds
		0x80, 0x0c, 0x70, 0x80, // Life Duration: 28800s

		// Transform 6: AES-256-CBC + SHA256 + PSK + DH (last)
		0x00, 0x00, 0x00, 0x24, 0x06, 0x01, 0x00, 0x00,
		0x80, 0x01, 0x00, 0x07, // Encryption: AES-CBC
		0x80, 0x0e, 0x01, 0x00, // Key Length: 256 bits
		0x80, 0x02, 0x00, 0x04, // Hash: SHA256
		0x80, 0x03, 0x00, 0x01, // Auth: PSK
		0x80, 0x04, dhHi, dhLo, // DH Group
		0x80, 0x0b, 0x00, 0x01, // Life Type: seconds
		0x80, 0x0c, 0x70, 0x80, // Life Duration: 28800s
	}
	// Proposal: protocol=ISAKMP, SPI-size=0, 6 transforms
	proposal := make([]byte, 8+len(transforms))
	proposal[4] = 0x01 // proposal #1
	proposal[5] = 0x01 // protocol: ISAKMP
	proposal[6] = 0x00 // SPI size: 0
	proposal[7] = 0x06 // # transforms: 6
	binary.BigEndian.PutUint16(proposal[2:4], uint16(len(proposal)))
	copy(proposal[8:], transforms)
	// SA payload: next=KE(4), DOI=IPSEC, Situation=SIT_IDENTITY_ONLY
	saPayload := make([]byte, 4+4+4+len(proposal))
	saPayload[0] = 0x04 // next: KE
	binary.BigEndian.PutUint16(saPayload[2:4], uint16(len(saPayload)))
	binary.BigEndian.PutUint32(saPayload[4:8], 1)  // DOI: IPSEC
	binary.BigEndian.PutUint32(saPayload[8:12], 1) // Situation: SIT_IDENTITY_ONLY
	copy(saPayload[12:], proposal)
	// KE payload: keSize bytes of zeros; next=Nonce(10)
	kePayload := make([]byte, 4+keSize)
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

// isIKEv1AggressiveResponse checks if a raw IKE response is from an IKEv1
// server that has Aggressive Mode enabled.
//
// Only exchange type 4 (Aggressive Mode) is treated as confirmation.
// INFORMATIONAL responses (exchange type 5) are NOT used to infer AM support
// because buggy Main-Mode-only implementations may respond with notifications
// like NO-PROPOSAL-CHOSEN without validating the exchange type, causing false
// positives.
func isIKEv1AggressiveResponse(data []byte) (aggressiveMode bool, ikev1Supported bool) {
	if !isPlausibleIKEPacket(data) {
		return false, false
	}
	majorVersion := (data[17] & 0xF0) >> 4
	exchangeType := data[18]
	if majorVersion == 1 {
		ikev1Supported = true
		if exchangeType == 4 {
			aggressiveMode = true
		}
	}
	return aggressiveMode, ikev1Supported
}

// --- Security Assessment Helpers ---
// detectWeakAlgorithms returns a list of weak algorithm names found in the SA proposals.
func detectWeakAlgorithms(
	encAlgs []commonprotocolfern.IkeEncryptionAlgorithm,
	hashAlgs []commonprotocolfern.IkeHashAlgorithm,
	dhGroups []commonprotocolfern.IkeDhGroup,
) []string {
	var weak []string
	weakEncryptionSet := weakAlgorithmSet(weakEncryptionAlgorithms)
	weakHashSet := weakAlgorithmSet(weakHashAlgorithms)
	weakDHSet := weakAlgorithmSet(weakDHGroups)

	for _, alg := range encAlgs {
		normalized := normalizeAlgorithmName(string(alg))
		if _, ok := weakEncryptionSet[normalized]; ok {
			weak = ikeprotocol.AppendUnique(weak, normalized)
		}
	}
	for _, alg := range hashAlgs {
		normalized := normalizeAlgorithmName(string(alg))
		if _, ok := weakHashSet[normalized]; ok {
			weak = ikeprotocol.AppendUnique(weak, normalized)
		}
	}
	for _, g := range dhGroups {
		normalized := normalizeAlgorithmName(string(g))
		if _, ok := weakDHSet[normalized]; ok {
			weak = ikeprotocol.AppendUnique(weak, normalized)
		}
	}
	return weak
}

func weakAlgorithmSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		set[normalizeAlgorithmName(item)] = struct{}{}
	}
	return set
}

func normalizeAlgorithmName(name string) string {
	return strings.ReplaceAll(name, "_", "-")
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

// stripNonESPMarker removes the 4-byte RFC 3948 Non-ESP marker (0x00000000)
// from the front of data if present, returning the remaining bytes.
func stripNonESPMarker(data []byte) []byte {
	if len(data) >= 4 && data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0 {
		return data[4:]
	}
	return data
}

// applyIKEv2ResponseToServerInfo parses an IKEv2 response packet and populates
// the corresponding fields on si. The caller must ensure data is a valid IKE
// packet (len >= 28) with any Non-ESP marker already stripped.
func applyIKEv2ResponseToServerInfo(data []byte, si *commonprotocolfern.IkeServerInfo) {
	header, err := ikeprotocol.ParseIKEHeader(data)
	if err != nil {
		return
	}
	ikev2 := header.MajorVersion == 2
	si.Ikev2Supported = &ikev2
	version := fmt.Sprintf("IKEv%d", header.MajorVersion)
	initiatorSPI := hex.EncodeToString(header.InitiatorSPI[:])
	responderSPI := hex.EncodeToString(header.ResponderSPI[:])
	exchangeType := ikeprotocol.GetExchangeTypeName(header.ExchangeType)
	flags := fmt.Sprintf("0x%02x", header.Flags)
	messageID := fmt.Sprintf("%d", header.MessageID)
	si.Version = &version
	si.InitiatorSpi = &initiatorSPI
	si.ResponderSpi = &responderSPI
	si.ExchangeType = &exchangeType
	si.Flags = &flags
	si.MessageId = &messageID
	vendorIDs, proposals := ikeprotocol.ParseIKEPayloads(data[28:], header.NextPayload)
	for _, vid := range vendorIDs {
		si.VendorIds = ikeprotocol.AppendUnique(si.VendorIds, vid)
	}
	si.EncryptionAlgorithms = ikeprotocol.MergeFernEncryptionAlgorithms(si.EncryptionAlgorithms, proposals.EncryptionAlgs)
	si.HashAlgorithms = ikeprotocol.MergeFernHashAlgorithms(si.HashAlgorithms, proposals.HashAlgs)
	si.AuthenticationMethods = ikeprotocol.MergeFernAuthenticationMethods(si.AuthenticationMethods, proposals.AuthMethods)
	si.DhGroups = ikeprotocol.MergeFernDHGroups(si.DhGroups, proposals.DHGroups)
}

// mergeIKEv1ProposalsIntoServerInfo appends unique algorithm names from
// proposals into the corresponding si slices.
func mergeIKEv1ProposalsIntoServerInfo(proposals *ikeprotocol.SecurityProposals, si *commonprotocolfern.IkeServerInfo) {
	si.EncryptionAlgorithms = ikeprotocol.MergeFernEncryptionAlgorithms(si.EncryptionAlgorithms, proposals.EncryptionAlgs)
	si.HashAlgorithms = ikeprotocol.MergeFernHashAlgorithms(si.HashAlgorithms, proposals.HashAlgs)
	si.AuthenticationMethods = ikeprotocol.MergeFernAuthenticationMethods(si.AuthenticationMethods, proposals.AuthMethods)
	si.DhGroups = ikeprotocol.MergeFernDHGroups(si.DhGroups, proposals.DHGroups)
}
