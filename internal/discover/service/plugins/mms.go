// Package plugins provides MMS (Manufacturing Message Specification) service fingerprinting
package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type MmsFingerprinter struct{}

func (MmsFingerprinter) Name() string { return "mms" }

func (MmsFingerprinter) DefaultPorts() []int { return []int{102} }

func (MmsFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := helpers.Dial(ctx, "tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	if err := helpers.SetDeadline(conn, timeout); err != nil {
		return nil, err
	}

	// MMS over ISO/IEC 8073 (COTP) and ISO/IEC 8327 (Session)
	// First send COTP Connection Request (RFC 1006/ISO 8073)
	cotpCR := buildCOTPConnectionRequest()

	// Send COTP CR
	if _, err := conn.Write(cotpCR); err != nil {
		return nil, err
	}

	// Read COTP response
	response := make([]byte, 2048)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// RFC 1006 TPKT header: version (3), reserved (0), length (2 bytes)
	if n < 7 {
		return nil, fmt.Errorf("response too short")
	}

	// Verify TPKT header
	if response[0] != 0x03 || response[1] != 0x00 {
		return nil, fmt.Errorf("invalid TPKT header")
	}

	// Parse TPKT length
	tpktLen := binary.BigEndian.Uint16(response[2:4])
	if int(tpktLen) > n {
		return nil, fmt.Errorf("incomplete TPKT packet")
	}

	// Check COTP header (should be Connection Confirm - 0xD0)
	if n < 5 || response[5] != 0xD0 {
		return nil, fmt.Errorf("not a COTP Connection Confirm")
	}

	// Extract MMS/COTP information
	var version, vendorName, modelName, revision *string

	// MMS typically uses ISO 9506
	versionStr := "MMS (ISO 9506)"
	version = &versionStr

	// Try to extract additional info from COTP parameters
	// Parse COTP parameters after the fixed header
	offset := 7 // Skip TPKT (4) + COTP fixed part (3)
	if offset < n {
		// Look for COTP parameters
		for offset+2 < n {
			paramCode := response[offset]
			paramLen := int(response[offset+1])

			if paramCode == 0xC1 { // src-tsap
				if offset+2+paramLen <= n {
					tsap := response[offset+2 : offset+2+paramLen]
					// Try to extract vendor info from TSAP
					if len(tsap) > 0 {
						tsapStr := string(tsap)
						vendorName = &tsapStr
					}
				}
			}

			offset += 2 + paramLen
			if offset >= n {
				break
			}
		}
	}

	metadata := &protocol.MmsServerInfo{
		Version:    version,
		VendorName: vendorName,
		ModelName:  modelName,
		Revision:   revision,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeMms,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Mms: metadata},
	}

	return result, nil
}

// buildCOTPConnectionRequest creates a COTP Connection Request over TPKT (RFC 1006)
func buildCOTPConnectionRequest() []byte {
	// TPKT Header (RFC 1006)
	tpkt := []byte{
		0x03,       // Version
		0x00,       // Reserved
		0x00, 0x16, // Length (22 bytes total)
	}

	// COTP Connection Request (ISO 8073)
	cotp := []byte{
		0x11,       // Length of COTP header minus 1 (17 bytes)
		0xE0,       // CR - Connection Request
		0x00, 0x00, // Destination Reference (0)
		0x00, 0x01, // Source Reference
		0x00, // Class and Options (Class 0)
		// Parameters
		0xC1, 0x02, 0x00, 0x01, // src-tsap
		0xC2, 0x02, 0x00, 0x01, // dst-tsap
		0xC0, 0x01, 0x0A, // TPDU Size (1024 bytes)
	}

	return append(tpkt, cotp...)
}
