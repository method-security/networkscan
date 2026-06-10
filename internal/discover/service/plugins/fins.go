// Package plugins provides FINS (Omron PLC) service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type FinsFingerprinter struct{}

func (FinsFingerprinter) Name() string { return "fins" }

func (FinsFingerprinter) DefaultPorts() []int { return []int{9600} }

func (FinsFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
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

	// FINS/TCP connection establishment
	// First, send a node address data send frame
	finsHandshake := []byte{
		0x46, 0x49, 0x4E, 0x53, // "FINS" header
		0x00, 0x00, 0x00, 0x0C, // Length: 12 bytes
		0x00, 0x00, 0x00, 0x00, // Command: Node address data send
		0x00, 0x00, 0x00, 0x00, // Error code: 0
		0x00, 0x00, 0x00, 0x00, // Client node address (0 = auto-assign)
	}

	// Send handshake
	if _, err := conn.Write(finsHandshake); err != nil {
		return nil, err
	}

	// Read handshake response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// FINS/TCP handshake response should have "FINS" header
	if n < 24 {
		return nil, fmt.Errorf("response too short")
	}

	// Verify FINS header
	if response[0] != 0x46 || response[1] != 0x49 || response[2] != 0x4E || response[3] != 0x53 {
		return nil, fmt.Errorf("invalid FINS response header")
	}

	// Extract node addresses from handshake response
	var nodeAddress, unitAddress *string
	var version *string

	// Client node address is at offset 16, server node address at offset 20
	if n >= 24 {
		clientNode := response[19]
		serverNode := response[23]
		nodeAddrStr := fmt.Sprintf("Client: %d, Server: %d", clientNode, serverNode)
		nodeAddress = &nodeAddrStr
	}

	// Now send a status read command to get PLC model
	// FINS command frame: header + command data
	statusReadCmd := []byte{
		0x46, 0x49, 0x4E, 0x53, // "FINS" header
		0x00, 0x00, 0x00, 0x1A, // Length: 26 bytes
		0x00, 0x00, 0x00, 0x02, // Command: FINS frame send
		0x00, 0x00, 0x00, 0x00, // Error code: 0
		// FINS command body
		0x80,       // ICF: Command
		0x00,       // RSV: Reserved
		0x02,       // GCT: Gateway count
		0x00,       // DNA: Destination network address
		0x00,       // DA1: Destination node address
		0x00,       // DA2: Destination unit address
		0x00,       // SNA: Source network address
		0x00,       // SA1: Source node address (will be filled by PLC)
		0x00,       // SA2: Source unit address
		0x00,       // SID: Service ID
		0x05, 0x01, // Command: Controller data read (05 01)
		0x00, 0x00, // Response code placeholder
	}

	if _, err := conn.Write(statusReadCmd); err == nil {
		statusResp := make([]byte, 1024)
		if n, err := conn.Read(statusResp); err == nil && n > 30 {
			// Check for successful response
			if statusResp[0] == 0x46 && statusResp[1] == 0x49 && statusResp[2] == 0x4E && statusResp[3] == 0x53 {
				// Extract PLC model from response (if available)
				if n > 50 {
					// Try to extract model information from response payload
					payload := statusResp[30:n]
					if len(payload) > 20 {
						// Look for ASCII strings that might indicate model
						modelStr := extractPrintableString(payload, 20)
						if modelStr != "" {
							plcModel := modelStr
							version = &plcModel
						}
					}
				}
			}
		}
	}

	if version == nil {
		versionStr := "FINS/TCP"
		version = &versionStr
	}

	metadata := &protocol.FinsServerInfo{
		Version:     version,
		PlcModel:    version,
		NodeAddress: nodeAddress,
		UnitAddress: unitAddress,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeFins,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Fins: metadata},
	}

	return result, nil
}

// extractPrintableString extracts a printable ASCII string from a byte slice
func extractPrintableString(data []byte, maxLen int) string {
	if len(data) > maxLen {
		data = data[:maxLen]
	}

	result := ""
	for _, b := range data {
		if b >= 32 && b <= 126 {
			result += string(b)
		} else if len(result) > 0 {
			break
		}
	}

	if len(result) > 3 {
		return result
	}
	return ""
}
