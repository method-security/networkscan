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
// buildIKEv1AggressiveModeProbe creates an IKEv1 Aggressive Mode probe packet.
// It proposes DES-CBC + MD5 + PSK + MODP-768 — the weakest common set — to
// maximize the chance that a configured server will accept and respond.
func buildIKEv1AggressiveModeProbe() []byte {
	// Three transforms, all using MODP-1024 to match the single KE payload.
	// Attributes use TV (Type-Value) format: MSB of type byte = 1.
	// Last/More byte: 0x03 = more transforms, 0x00 = last transform.
	transforms := []byte{
		// Transform 1: 3DES-CBC + SHA1 + PSK + MODP-1024 (most widely supported)
		0x03, 0x00, 0x00, 0x20, 0x01, 0x01, 0x00, 0x00,
		0x80, 0x01, 0x00, 0x05, // Encryption: 3DES-CBC
		0x80, 0x02, 0x00, 0x02, // Hash: SHA1
		0x80, 0x03, 0x00, 0x01, // Auth: PSK
		0x80, 0x04, 0x00, 0x02, // DH Group: MODP-1024
		0x80, 0x0b, 0x00, 0x01, // Life Type: seconds
		0x80, 0x0c, 0x70, 0x80, // Life Duration: 28800s

		// Transform 2: AES-128-CBC + SHA1 + PSK + MODP-1024
		0x03, 0x00, 0x00, 0x24, 0x02, 0x01, 0x00, 0x00,
		0x80, 0x01, 0x00, 0x07, // Encryption: AES-CBC
		0x80, 0x0e, 0x00, 0x80, // Key Length: 128 bits
		0x80, 0x02, 0x00, 0x02, // Hash: SHA1
		0x80, 0x03, 0x00, 0x01, // Auth: PSK
		0x80, 0x04, 0x00, 0x02, // DH Group: MODP-1024
		0x80, 0x0b, 0x00, 0x01, // Life Type: seconds
		0x80, 0x0c, 0x70, 0x80, // Life Duration: 28800s

		// Transform 3: AES-256-CBC + SHA1 + PSK + MODP-1024 (last)
		0x00, 0x00, 0x00, 0x24, 0x03, 0x01, 0x00, 0x00,
		0x80, 0x01, 0x00, 0x07, // Encryption: AES-CBC
		0x80, 0x0e, 0x01, 0x00, // Key Length: 256 bits
		0x80, 0x02, 0x00, 0x02, // Hash: SHA1
		0x80, 0x03, 0x00, 0x01, // Auth: PSK
		0x80, 0x04, 0x00, 0x02, // DH Group: MODP-1024
		0x80, 0x0b, 0x00, 0x01, // Life Type: seconds
		0x80, 0x0c, 0x70, 0x80, // Life Duration: 28800s
	}
	// Proposal: protocol=ISAKMP, SPI-size=0, 3 transforms
	proposal := make([]byte, 8+len(transforms))
	proposal[4] = 0x01 // proposal #1
	proposal[5] = 0x01 // protocol: ISAKMP
	proposal[6] = 0x00 // SPI size: 0
	proposal[7] = 0x03 // # transforms: 3
	binary.BigEndian.PutUint16(proposal[2:4], uint16(len(proposal)))
	copy(proposal[8:], transforms)
	// SA payload: next=KE(4), DOI=IPSEC, Situation=SIT_IDENTITY_ONLY
	saPayload := make([]byte, 4+4+4+len(proposal))
	saPayload[0] = 0x04 // next: KE
	binary.BigEndian.PutUint16(saPayload[2:4], uint16(len(saPayload)))
	binary.BigEndian.PutUint32(saPayload[4:8], 1)  // DOI: IPSEC
	binary.BigEndian.PutUint32(saPayload[8:12], 1) // Situation: SIT_IDENTITY_ONLY
	copy(saPayload[12:], proposal)
	// KE payload: MODP-1024 = 128 bytes of zeros; next=Nonce(10)
	kePayload := make([]byte, 4+128)
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
// Exchange type 4 (Aggressive Mode) is direct confirmation. Exchange type 5
// (INFORMATIONAL) is also treated as confirmation unless the Notification
// payload contains INVALID-EXCHANGE-TYPE (type 7), which means the server
// explicitly rejected the AM exchange type and only supports Main Mode. Any
// other notification type (e.g. NO-PROPOSAL-CHOSEN=14, INVALID-ID-INFORMATION=18)
// means the server accepted the AM exchange type but rejected our specific
// proposal or identity — so AM is supported.
//
// It first validates the packet is a plausible IKE packet by checking the
// length field matches the actual data, to avoid false positives from non-IKE
// protocols.
func isIKEv1AggressiveResponse(data []byte) (aggressiveMode bool, ikev1Supported bool) {
	if !isPlausibleIKEPacket(data) {
		return false, false
	}
	majorVersion := (data[17] & 0xF0) >> 4
	exchangeType := data[18]
	if majorVersion == 1 {
		ikev1Supported = true
		switch exchangeType {
		case 4: // Aggressive Mode — direct confirmation
			aggressiveMode = true
		case 5: // Informational — infer from notification type
			// INVALID-EXCHANGE-TYPE (7) means server rejected AM entirely.
			// Any other non-zero notification means AM was accepted but our SA or ID was rejected.
			const invalidExchangeType = 7
			notifyType := ikeprotocol.ParseIKEv1NotificationType(data)
			aggressiveMode = notifyType != 0 && notifyType != invalidExchangeType
		}
	}
	return aggressiveMode, ikev1Supported
}

// --- Security Assessment Helpers ---
// detectWeakAlgorithms returns a list of weak algorithm names found in the SA proposals.
func detectWeakAlgorithms(encAlgs, hashAlgs, dhGroups []string) []string {
	var weak []string
	for _, alg := range encAlgs {
		for _, w := range weakEncryptionAlgorithms {
			if alg == w {
				weak = ikeprotocol.AppendUnique(weak, alg)
			}
		}
	}
	for _, alg := range hashAlgs {
		for _, w := range weakHashAlgorithms {
			if alg == w {
				weak = ikeprotocol.AppendUnique(weak, alg)
			}
		}
	}
	for _, g := range dhGroups {
		for _, w := range weakDHGroups {
			if g == w {
				weak = ikeprotocol.AppendUnique(weak, g)
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
	si.VendorIds = vendorIDs
	si.EncryptionAlgorithms = proposals.EncryptionAlgs
	si.HashAlgorithms = proposals.HashAlgs
	si.AuthenticationMethods = proposals.AuthMethods
	si.DhGroups = proposals.DHGroups
}

// mergeIKEv1ProposalsIntoServerInfo appends unique algorithm names from
// proposals into the corresponding si slices.
func mergeIKEv1ProposalsIntoServerInfo(proposals *ikeprotocol.SecurityProposals, si *commonprotocolfern.IkeServerInfo) {
	for _, a := range proposals.EncryptionAlgs {
		si.EncryptionAlgorithms = ikeprotocol.AppendUnique(si.EncryptionAlgorithms, a)
	}
	for _, a := range proposals.HashAlgs {
		si.HashAlgorithms = ikeprotocol.AppendUnique(si.HashAlgorithms, a)
	}
	for _, g := range proposals.DHGroups {
		si.DhGroups = ikeprotocol.AppendUnique(si.DhGroups, g)
	}
}
