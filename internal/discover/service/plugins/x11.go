// Package plugins provides X11 service fingerprinting
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

type X11Fingerprinter struct{}

func (X11Fingerprinter) Name() string { return "x11" }

func (X11Fingerprinter) DefaultPorts() []int {
	// X11 typically runs on ports 6000-6063 (for displays :0 to :63)
	ports := make([]int, 64)
	for i := 0; i < 64; i++ {
		ports[i] = 6000 + i
	}
	return ports
}

func (X11Fingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
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

	// X11 connection setup message
	// Format: byte-order + pad + major-version + minor-version + auth-proto-name-len + auth-proto-data-len + pad
	connectionSetup := []byte{
		0x6c,       // Byte order: 'l' for little-endian (0x42 'B' for big-endian)
		0x00,       // Pad
		0x0b, 0x00, // Protocol major version (11)
		0x00, 0x00, // Protocol minor version (0)
		0x00, 0x00, // Authorization protocol name length
		0x00, 0x00, // Authorization protocol data length
		0x00, 0x00, // Pad
	}

	// Send connection setup
	if _, err := conn.Write(connectionSetup); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	if n < 8 {
		return nil, fmt.Errorf("response too short")
	}

	// Parse X11 response
	// Byte 0: success (1), failed (0), or authenticate (2)
	status := response[0]

	// Check if this is a valid X11 response
	if status != 0 && status != 1 && status != 2 {
		return nil, fmt.Errorf("invalid X11 response status: %d", status)
	}

	var protocolMajor, protocolMinor *int
	var vendor, version *string
	var releaseNumber *int
	var authRequired *bool

	// Parse based on response status
	if status == 1 {
		// Success - parse server information
		// Bytes 2-3: protocol-major-version
		// Bytes 4-5: protocol-minor-version
		if n >= 6 {
			major := int(binary.LittleEndian.Uint16(response[2:4]))
			minor := int(binary.LittleEndian.Uint16(response[4:6]))
			protocolMajor = &major
			protocolMinor = &minor

			versionStr := fmt.Sprintf("X11R%d.%d", major, minor)
			version = &versionStr
		}

		// Bytes 6-7: length of additional data
		if n >= 8 {
			additionalDataLen := int(binary.LittleEndian.Uint16(response[6:8]))

			// Parse additional data which includes vendor information
			if n >= 40 {
				// Bytes 8-11: release-number
				rel := int(binary.LittleEndian.Uint32(response[8:12]))
				releaseNumber = &rel

				// Bytes 24-25: vendor length
				vendorLen := int(binary.LittleEndian.Uint16(response[24:26]))

				// Vendor string starts at byte 40
				if n >= 40+vendorLen && vendorLen > 0 && vendorLen < 256 {
					vendorStr := string(response[40 : 40+vendorLen])
					vendor = &vendorStr
				}
			}

			_ = additionalDataLen // Used for validation if needed
		}

		authReq := false
		authRequired = &authReq

	} else if status == 0 {
		// Failed - authentication required or other error
		authReq := true
		authRequired = &authReq

		// Protocol version might still be in the response
		if n >= 6 {
			major := int(binary.LittleEndian.Uint16(response[2:4]))
			minor := int(binary.LittleEndian.Uint16(response[4:6]))
			protocolMajor = &major
			protocolMinor = &minor

			versionStr := fmt.Sprintf("X11R%d.%d", major, minor)
			version = &versionStr
		}
	} else if status == 2 {
		// Authenticate - server requires authentication
		authReq := true
		authRequired = &authReq
	}

	metadata := &protocol.X11ServerInfo{
		Version:       version,
		ProtocolMajor: protocolMajor,
		ProtocolMinor: protocolMinor,
		Vendor:        vendor,
		ReleaseNumber: releaseNumber,
		AuthRequired:  authRequired,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeX11,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{X11: metadata},
	}

	return result, nil
}
