package plugins

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type UnistreamFingerprinter struct{}

func (UnistreamFingerprinter) Name() string { return "unistream" }

func (UnistreamFingerprinter) DefaultPorts() []int { return []int{44818} }

func (UnistreamFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	// Create connection with timeout
	dialer := net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	// EtherNet/IP List Identity request
	// EtherNet/IP encapsulation header: Command 0x0063 (List Identity)
	ethernetIPRequest := []byte{
		0x63, 0x00, // Command: List Identity (0x0063)
		0x00, 0x00, // Length: 0 (no data)
		0x00, 0x00, 0x00, 0x00, // Session Handle: 0
		0x00, 0x00, 0x00, 0x00, // Status: 0 (success)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sender Context: 8 bytes of 0
		0x00, 0x00, 0x00, 0x00, // Options: 0
	}

	// Send List Identity request
	if _, err := conn.Write(ethernetIPRequest); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// EtherNet/IP List Identity response should be at least 24 bytes (header)
	if n < 24 {
		return nil, fmt.Errorf("response too short")
	}

	// Verify EtherNet/IP List Identity response header
	// Command should be 0x0063, Status should be 0x0000 (success)
	if response[0] != 0x63 || response[1] != 0x00 {
		return nil, fmt.Errorf("invalid EtherNet/IP command response")
	}

	// Check status (bytes 8-11 should be 0x00000000 for success)
	if response[8] != 0x00 || response[9] != 0x00 || response[10] != 0x00 || response[11] != 0x00 {
		return nil, fmt.Errorf("EtherNet/IP error status")
	}

	// Extract device information from List Identity response
	var productName, vendorID, serialNumber, deviceType, deviceIP *string

	// Convert response to string for pattern matching - EtherNet/IP can contain readable strings
	responseStr := string(response[:n])

	// Look for Unitronics/UniStream indicators first
	if strings.Contains(strings.ToLower(responseStr), "unistream") {
		product := "Unistream"
		productName = &product
	}

	if strings.Contains(strings.ToLower(responseStr), "unitronics") {
		vendor := "Unitronics (1989) (RG) LTD"
		vendorID = &vendor
	}

	// Try to extract fields using regex patterns from readable strings in the response
	patterns := map[string]**string{
		`Product name:\s*([^\r\n]+)`:                                    &productName,
		`Vendor ID:\s*([^\r\n]+)`:                                       &vendorID,
		`Serial number:\s*(0x[a-fA-F0-9]+|[0-9]+)`:                      &serialNumber,
		`Device type:\s*([^\r\n]+)`:                                     &deviceType,
		`Device IP:\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})`: &deviceIP,
	}

	for pattern, field := range patterns {
		if re := regexp.MustCompile(pattern); re != nil {
			if matches := re.FindStringSubmatch(responseStr); len(matches) > 1 {
				value := strings.TrimSpace(matches[1])
				if value != "" {
					*field = &value
				}
			}
		}
	}

	// Parse the identity item structure for additional data (starts at byte 24 if present)
	if n > 24 {
		pos := 24
		for pos < n-6 {
			// Check for Identity Item (Type ID 0x000C)
			if pos+6 < n && response[pos] == 0x0C && response[pos+1] == 0x00 {
				// Extract length of identity data
				length := int(response[pos+2]) | (int(response[pos+3]) << 8)
				if pos+6+length <= n {
					identityData := response[pos+6 : pos+6+length]

					// Extract any additional readable strings from binary data
					if len(identityData) >= 8 && productName == nil {
						productNameStr := extractStringFromIdentity(identityData, length)
						if productNameStr != "" {
							productName = &productNameStr
						}
					}
				}
				break
			}
			pos++
		}
	}

	// Set version based on detection
	var version *string
	if productName != nil || vendorID != nil {
		versionStr := "EtherNet/IP"
		version = &versionStr
	}

	metadata := &protocol.UnistreamServerInfo{
		Version:      version,
		ProductName:  productName,
		VendorId:     vendorID,
		SerialNumber: serialNumber,
		DeviceType:   deviceType,
		DeviceIp:     deviceIP,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeEthernetip,
		Version:   version,
		Metadata:  discoverfern.NewServiceMetadataFromUnistream(metadata),
	}

	return result, nil
}

// extractStringFromIdentity extracts printable strings from EtherNet/IP identity data
func extractStringFromIdentity(data []byte, length int) string {
	// Look for printable ASCII strings in the identity data
	var result strings.Builder
	inString := false

	for i := 0; i < len(data) && i < length; i++ {
		char := data[i]
		if char >= 32 && char <= 126 { // Printable ASCII
			if !inString {
				if result.Len() > 0 {
					result.WriteString(" ")
				}
				inString = true
			}
			result.WriteByte(char)
		} else if inString {
			inString = false
		}
	}

	str := result.String()

	// Clean up the extracted string
	str = strings.TrimSpace(str)

	// Return only if it looks like useful device information
	if len(str) > 3 && len(str) < 100 {
		return str
	}

	return ""
}
