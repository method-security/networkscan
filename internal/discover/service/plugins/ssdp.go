// Package plugins provides SSDP (Simple Service Discovery Protocol) service fingerprinting
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

type SSDPFingerprinter struct{}

func (SSDPFingerprinter) Name() string { return "ssdp" }

func (SSDPFingerprinter) DefaultPorts() []int { return []int{1900} }

func (SSDPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := utils.FormatHostPort(ip.String(), port)

	// SSDP M-SEARCH discovery request
	msearchRequest := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"

	conn, err := helpers.Dial(ctx, "udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	if err := helpers.SetDeadline(conn, timeout); err != nil {
		return nil, err
	}

	// Send M-SEARCH request
	if _, err := conn.Write([]byte(msearchRequest)); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	responseStr := string(response[:n])

	// Check for SSDP response signature
	if !strings.HasPrefix(responseStr, "HTTP/1.1") {
		return nil, fmt.Errorf("not an SSDP response")
	}

	// Build typed metadata
	metadata := &protocol.SsdpServerInfo{}
	var version *string

	// Parse response headers
	lines := strings.Split(responseStr, "\r\n")
	if len(lines) > 0 {
		status := lines[0]
		metadata.Status = &status
	}

	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToUpper(line), "SERVER:") {
			server := strings.TrimSpace(line[7:])
			version = &server
			metadata.Server = &server
		} else if strings.HasPrefix(strings.ToUpper(line), "LOCATION:") {
			location := strings.TrimSpace(line[9:])
			metadata.Location = &location
		} else if strings.HasPrefix(strings.ToUpper(line), "ST:") {
			st := strings.TrimSpace(line[3:])
			metadata.ServiceType = &st
		} else if strings.HasPrefix(strings.ToUpper(line), "USN:") {
			usn := strings.TrimSpace(line[4:])
			metadata.Usn = &usn
		} else if strings.HasPrefix(strings.ToUpper(line), "CACHE-CONTROL:") {
			cacheControl := strings.TrimSpace(line[14:])
			metadata.CacheControl = &cacheControl
		}
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeSsdp,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Ssdp: metadata},
	}

	return result, nil
}
