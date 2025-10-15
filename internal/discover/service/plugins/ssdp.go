// Package plugins provides SSDP (Simple Service Discovery Protocol) service fingerprinting
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

type SSDPFingerprinter struct{}

func (SSDPFingerprinter) Name() string { return "ssdp" }

func (SSDPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	// SSDP M-SEARCH discovery request
	msearchRequest := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"

	conn, err := net.DialTimeout("udp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	if err := conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
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

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeSsdp,
		Metadata:  make(map[string]string),
	}

	// Parse response headers
	lines := strings.Split(responseStr, "\r\n")
	if len(lines) > 0 {
		result.Metadata["status"] = lines[0]
	}

	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToUpper(line), "SERVER:") {
			server := strings.TrimSpace(line[7:])
			result.Version = &server
			result.Metadata["server"] = server
		} else if strings.HasPrefix(strings.ToUpper(line), "LOCATION:") {
			location := strings.TrimSpace(line[9:])
			result.Metadata["location"] = location
		} else if strings.HasPrefix(strings.ToUpper(line), "ST:") {
			st := strings.TrimSpace(line[3:])
			result.Metadata["service_type"] = st
		} else if strings.HasPrefix(strings.ToUpper(line), "USN:") {
			usn := strings.TrimSpace(line[4:])
			result.Metadata["usn"] = usn
		} else if strings.HasPrefix(strings.ToUpper(line), "CACHE-CONTROL:") {
			cacheControl := strings.TrimSpace(line[14:])
			result.Metadata["cache_control"] = cacheControl
		}
	}

	return result, nil
}
