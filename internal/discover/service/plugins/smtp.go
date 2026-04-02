// Package plugins provides SMTP service fingerprinting
package plugins

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type SMTPFingerprinter struct{}

func (SMTPFingerprinter) Name() string { return "smtp" }

func (SMTPFingerprinter) DefaultPorts() []int { return []int{25, 465, 587, 2525, 8025} }

func (SMTPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	dur := time.Duration(timeout) * time.Second

	dialer := net.Dialer{Timeout: dur}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(dur))

	// Read the banner — SMTP servers send a 220 greeting on connect.
	// Banners can be multi-line (220- continuation lines followed by a final 220 line).
	reader := bufio.NewReader(conn)
	var bannerLines []string
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			return nil, readErr
		}
		line = strings.TrimSpace(line)

		if !strings.HasPrefix(line, "220") {
			return nil, fmt.Errorf("not an SMTP service: %s", line)
		}
		bannerLines = append(bannerLines, line)

		// "220 " (space at index 3) is the final banner line
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
		// Single "220" with no continuation marker is also final
		if len(line) < 4 {
			break
		}
	}

	banner := bannerLines[0]

	// Parse banner for server info
	serverName, softwareName, softwareVersion := parseSMTPBanner(banner)
	esmtp := strings.Contains(banner, "ESMTP")

	// Send EHLO to discover capabilities
	_ = conn.SetWriteDeadline(time.Now().Add(dur))
	ehloHost := "scanner.local"
	_, err = fmt.Fprintf(conn, "EHLO %s\r\n", ehloHost)
	if err != nil {
		return buildSMTPResult(host, ip, port, banner, serverName, softwareName, softwareVersion, esmtp, false, nil, nil), nil
	}

	_ = conn.SetReadDeadline(time.Now().Add(dur))

	var extensions []string
	var authMethods []string
	tlsSupported := false

	// Read EHLO response lines — only accept 250 responses
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			break
		}
		line = strings.TrimSpace(line)

		if len(line) < 4 {
			break
		}

		// Only process 250 response lines; anything else means EHLO failed or unexpected response
		if !strings.HasPrefix(line, "250") {
			break
		}

		ext := line[4:]

		if strings.HasPrefix(strings.ToUpper(ext), "STARTTLS") {
			tlsSupported = true
		}
		if strings.HasPrefix(strings.ToUpper(ext), "AUTH ") {
			methods := strings.Fields(ext)
			if len(methods) > 1 {
				authMethods = append(authMethods, methods[1:]...)
			}
		}
		extensions = append(extensions, ext)

		// "250 " (space, not dash) means last line
		if line[3] == ' ' {
			break
		}
	}

	// Send QUIT
	_ = conn.SetWriteDeadline(time.Now().Add(dur))
	_, _ = fmt.Fprintf(conn, "QUIT\r\n")

	return buildSMTPResult(host, ip, port, banner, serverName, softwareName, softwareVersion, esmtp, tlsSupported, authMethods, extensions), nil
}

func buildSMTPResult(host string, ip net.IP, port int, banner, serverName, softwareName, softwareVersion string, esmtp, tlsSupported bool, authMethods, extensions []string) *discoverfern.ServiceDetails {
	metadata := &protocol.SmtpServerInfo{
		Banner:              &banner,
		EsmtpSupported:      &esmtp,
		TlsSupported:        &tlsSupported,
		AuthMethods:         authMethods,
		SupportedExtensions: extensions,
	}
	if serverName != "" {
		metadata.ServerName = &serverName
	}
	if softwareName != "" {
		metadata.SoftwareName = &softwareName
	}
	if softwareVersion != "" {
		metadata.SoftwareVersion = &softwareVersion
	}

	version := banner
	if softwareName != "" {
		version = softwareName
		if softwareVersion != "" {
			version += " " + softwareVersion
		}
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeSmtp,
		Version:   &version,
		Metadata:  discoverfern.NewServiceMetadataFromSmtp(metadata),
	}
}

// parseSMTPBanner extracts server name and software info from a 220 banner.
// Common formats:
//
//	"220 mail.example.com ESMTP Postfix"
//	"220 mail.example.com ESMTP hMailServer 5.6.9"
//	"220-mail.example.com ESMTP"
func parseSMTPBanner(banner string) (serverName, softwareName, softwareVersion string) {
	// Strip the 220 code and any continuation marker
	line := banner
	if strings.HasPrefix(line, "220-") {
		line = line[4:]
	} else if strings.HasPrefix(line, "220 ") {
		line = line[4:]
	} else {
		return
	}

	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}

	serverName = parts[0]

	// Skip ESMTP/SMTP marker to find software name
	idx := 1
	for idx < len(parts) {
		upper := strings.ToUpper(parts[idx])
		if upper == "ESMTP" || upper == "SMTP" {
			idx++
			break
		}
		idx++
	}

	if idx < len(parts) {
		// Remaining parts are software name + possible version
		remaining := parts[idx:]
		// Try to find version-like token (starts with digit)
		for i, token := range remaining {
			if len(token) > 0 && token[0] >= '0' && token[0] <= '9' {
				softwareName = strings.Join(remaining[:i], " ")
				softwareVersion = strings.Join(remaining[i:], " ")
				return
			}
		}
		softwareName = strings.Join(remaining, " ")
	}

	return
}
