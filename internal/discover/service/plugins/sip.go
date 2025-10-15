// Package plugins provides SIP (Session Initiation Protocol) service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type SIPFingerprinter struct{}

func (SIPFingerprinter) Name() string { return "sip" }

func (SIPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	// Create SIP OPTIONS request
	sipRequest := fmt.Sprintf(
		"OPTIONS sip:%s SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK776asdhds\r\n"+
			"Max-Forwards: 70\r\n"+
			"To: <sip:%s>\r\n"+
			"From: <sip:scanner@localhost>;tag=1928301774\r\n"+
			"Call-ID: a84b4c76e66710@localhost\r\n"+
			"CSeq: 63104 OPTIONS\r\n"+
			"Contact: <sip:scanner@%s:5060>\r\n"+
			"Accept: application/sdp\r\n"+
			"Content-Length: 0\r\n"+
			"\r\n",
		ip, ip, ip, ip,
	)

	// Try UDP first (most common for SIP)
	conn, err := net.DialTimeout("udp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	if err := conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
		return nil, err
	}

	// Send SIP OPTIONS request
	if _, err := conn.Write([]byte(sipRequest)); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	responseStr := string(response[:n])

	// Check for SIP response signature
	if !strings.HasPrefix(responseStr, "SIP/2.0") {
		return nil, fmt.Errorf("not a SIP response")
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeSip,
		Metadata:  make(map[string]string),
	}

	// Parse response
	lines := strings.Split(responseStr, "\r\n")
	if len(lines) > 0 {
		// First line is status line
		statusLine := lines[0]
		result.Metadata["status"] = statusLine

		// Parse headers
		for _, line := range lines[1:] {
			if line == "" {
				break
			}
			if strings.HasPrefix(line, "Server:") {
				server := strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
				result.Version = &server
				result.Metadata["server"] = server
			} else if strings.HasPrefix(line, "User-Agent:") {
				userAgent := strings.TrimSpace(strings.TrimPrefix(line, "User-Agent:"))
				if result.Version == nil {
					result.Version = &userAgent
				}
				result.Metadata["user_agent"] = userAgent
			} else if strings.HasPrefix(line, "Allow:") {
				allow := strings.TrimSpace(strings.TrimPrefix(line, "Allow:"))
				result.Metadata["allow"] = allow
			}
		}
	}

	return result, nil
}
