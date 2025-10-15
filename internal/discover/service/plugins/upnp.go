// Package plugins provides UPnP (Universal Plug and Play) service fingerprinting
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

type UPnPFingerprinter struct{}

func (UPnPFingerprinter) Name() string { return "upnp" }

func (UPnPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	// UPnP uses SSDP (Simple Service Discovery Protocol) over UDP multicast
	// Send M-SEARCH discovery request
	msearchRequest := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
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

	// Check for UPnP/SSDP response
	if !strings.HasPrefix(responseStr, "HTTP/1.1 200 OK") &&
		!strings.Contains(responseStr, "upnp") &&
		!strings.Contains(responseStr, "SSDP") {
		return nil, fmt.Errorf("not a UPnP response")
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeUpnp,
		Metadata:  make(map[string]string),
	}

	// Parse response headers
	lines := strings.Split(responseStr, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Server:") || strings.HasPrefix(line, "SERVER:") {
			server := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "Server:"), "SERVER:"))
			result.Version = &server
			result.Metadata["server"] = server
		} else if strings.HasPrefix(line, "Location:") || strings.HasPrefix(line, "LOCATION:") {
			location := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "Location:"), "LOCATION:"))
			result.Metadata["location"] = location
		} else if strings.HasPrefix(line, "ST:") {
			st := strings.TrimSpace(strings.TrimPrefix(line, "ST:"))
			result.Metadata["service_type"] = st
		} else if strings.HasPrefix(line, "USN:") {
			usn := strings.TrimSpace(strings.TrimPrefix(line, "USN:"))
			result.Metadata["usn"] = usn
		}
	}

	return result, nil
}
