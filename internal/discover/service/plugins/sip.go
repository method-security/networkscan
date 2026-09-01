// Package plugins provides SIP (Session Initiation Protocol) service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	"github.com/Method-Security/networkscan/utils"
)

type SIPFingerprinter struct{}

func (SIPFingerprinter) Name() string { return "sip" }

func (SIPFingerprinter) DefaultPorts() []int { return []int{5060} }

func (SIPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := utils.FormatHostPort(ip.String(), port)

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
	conn, err := helpers.Dial(ctx, "udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	if err := helpers.SetDeadline(conn, timeout); err != nil {
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

	// Parse response first to extract metadata
	var statusLine, server, userAgent, allow *string
	var version *string

	lines := strings.Split(responseStr, "\r\n")
	if len(lines) > 0 {
		// First line is status line
		sl := lines[0]
		statusLine = &sl

		// Parse headers
		for _, line := range lines[1:] {
			if line == "" {
				break
			}
			if strings.HasPrefix(line, "Server:") {
				s := strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
				server = &s
				version = &s
			} else if strings.HasPrefix(line, "User-Agent:") {
				ua := strings.TrimSpace(strings.TrimPrefix(line, "User-Agent:"))
				userAgent = &ua
				if version == nil {
					version = &ua
				}
			} else if strings.HasPrefix(line, "Allow:") {
				a := strings.TrimSpace(strings.TrimPrefix(line, "Allow:"))
				allow = &a
			}
		}
	}

	metadata := &protocol.SipServerInfo{
		Status:    statusLine,
		Server:    server,
		UserAgent: userAgent,
		Allow:     allow,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeSip,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Sip: metadata},
	}

	return result, nil
}
