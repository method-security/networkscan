// Package plugins provides NTP service fingerprinting
package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type NTPFingerprinter struct{}

func (NTPFingerprinter) Name() string { return "ntp" }

func (NTPFingerprinter) DefaultPorts() []int { return []int{123} }

func (NTPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	// Create UDP connection
	conn, err := helpers.Dial(ctx, "udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read deadline
	if err := helpers.SetReadDeadline(conn, timeout); err != nil {
		return nil, err
	}

	// Build NTP request packet (48 bytes)
	ntpRequest := buildNTPRequest()

	// Send the request
	if _, err := conn.Write(ntpRequest); err != nil {
		return nil, err
	}

	// Read response
	buffer := make([]byte, 65535)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	// Extension fields and authentication data may follow the fixed header.
	if n < 48 {
		return nil, fmt.Errorf("invalid NTP response size: %d", n)
	}

	// Parse NTP response header
	leapIndicator := (buffer[0] >> 6) & 0x03
	versionNumber := (buffer[0] >> 3) & 0x07
	mode := buffer[0] & 0x07
	stratum := buffer[1]

	if mode != 4 || versionNumber < 1 || versionNumber > 4 || stratum > 16 {
		return nil, fmt.Errorf("invalid NTP server header")
	}
	if !bytes.Equal(buffer[24:32], ntpRequest[40:48]) {
		return nil, fmt.Errorf("NTP origin timestamp does not match request")
	}

	version := fmt.Sprintf("%d", versionNumber)
	ntpVersion := fmt.Sprintf("%d", versionNumber)
	stratumStr := fmt.Sprintf("%d", stratum)
	leapIndicatorStr := getLeapIndicatorString(leapIndicator)
	modeStr := getNTPModeString(mode)

	var referenceID *string
	var referenceIP *string

	// Parse reference identifier (bytes 12-15)
	if stratum <= 1 {
		// For stratum 1, reference ID is an ASCII string (reference clock identifier)
		refID := string(buffer[12:16])
		referenceID = &refID
	} else if stratum > 1 {
		// For stratum > 1, reference ID is an IP address
		refIP := net.IPv4(buffer[12], buffer[13], buffer[14], buffer[15]).String()
		referenceIP = &refIP
	}

	metadata := &protocol.NtpServerInfo{
		Version:       &ntpVersion,
		Stratum:       &stratumStr,
		LeapIndicator: &leapIndicatorStr,
		Mode:          &modeStr,
		ReferenceId:   referenceID,
		ReferenceIp:   referenceIP,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeNtp,
		Version:   &version,
		Metadata:  &discoverfern.ServiceMetadata{Ntp: metadata},
	}

	return result, nil
}

// buildNTPRequest creates an NTP client request packet
func buildNTPRequest() []byte {
	packet := make([]byte, 48)

	// Set Leap Indicator (0), Version (3), and Mode (3 = client)
	packet[0] = 0x1B // 00 011 011 = LI=0, Version=3, Mode=3

	// The server echoes this timestamp in its origin field.
	now := time.Now()
	binary.BigEndian.PutUint32(packet[40:44], uint32(now.Unix()+2208988800))
	binary.BigEndian.PutUint32(packet[44:48], uint32((uint64(now.Nanosecond())<<32)/1000000000))

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
