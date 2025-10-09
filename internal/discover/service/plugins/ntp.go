// Package plugins provides NTP service fingerprinting
package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type NTPFingerprinter struct{}

func (NTPFingerprinter) Name() string { return "ntp" }

func (NTPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)

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

	// Build NTP request packet (48 bytes)
	ntpRequest := buildNTPRequest()

	// Send the request
	if _, err := conn.Write(ntpRequest); err != nil {
		return nil, err
	}

	// Read response
	buffer := make([]byte, 48)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	// NTP response must be exactly 48 bytes
	if n != 48 {
		return nil, fmt.Errorf("invalid NTP response size: %d", n)
	}

	// Parse NTP response header
	leapIndicator := (buffer[0] >> 6) & 0x03
	versionNumber := (buffer[0] >> 3) & 0x07
	mode := buffer[0] & 0x07
	stratum := buffer[1]

	// Validate it's an NTP response (mode should be 4 for server response)
	if mode != 4 && mode != 5 {
		return nil, fmt.Errorf("invalid NTP mode: %d", mode)
	}

	// NTP service detected
	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeNtp,
		Metadata:  make(map[string]string),
	}

	version := fmt.Sprintf("NTPv%d", versionNumber)
	result.Version = &version
	result.Metadata["ntp_version"] = fmt.Sprintf("%d", versionNumber)
	result.Metadata["stratum"] = fmt.Sprintf("%d", stratum)
	result.Metadata["leap_indicator"] = getLeapIndicatorString(leapIndicator)
	result.Metadata["mode"] = getNTPModeString(mode)

	// Parse reference identifier (bytes 12-15)
	if stratum == 1 {
		// For stratum 1, reference ID is an ASCII string (reference clock identifier)
		refID := string(buffer[12:16])
		result.Metadata["reference_id"] = refID
	} else if stratum > 1 {
		// For stratum > 1, reference ID is an IP address
		refIP := net.IPv4(buffer[12], buffer[13], buffer[14], buffer[15])
		result.Metadata["reference_ip"] = refIP.String()
	}

	return result, nil
}

// buildNTPRequest creates an NTP client request packet
func buildNTPRequest() []byte {
	packet := make([]byte, 48)

	// Set Leap Indicator (0), Version (3), and Mode (3 = client)
	packet[0] = 0x1B // 00 011 011 = LI=0, Version=3, Mode=3

	// All other fields can remain zero for a basic request

	return packet
}

// getLeapIndicatorString returns a human-readable leap indicator string
func getLeapIndicatorString(li byte) string {
	switch li {
	case 0:
		return "no warning"
	case 1:
		return "last minute has 61 seconds"
	case 2:
		return "last minute has 59 seconds"
	case 3:
		return "alarm condition (clock not synchronized)"
	default:
		return "unknown"
	}
}

// getNTPModeString returns a human-readable NTP mode string
func getNTPModeString(mode byte) string {
	switch mode {
	case 0:
		return "reserved"
	case 1:
		return "symmetric active"
	case 2:
		return "symmetric passive"
	case 3:
		return "client"
	case 4:
		return "server"
	case 5:
		return "broadcast"
	case 6:
		return "NTP control message"
	case 7:
		return "reserved for private use"
	default:
		return "unknown"
	}
}

// Prevent unused import warning
var _ = binary.BigEndian
