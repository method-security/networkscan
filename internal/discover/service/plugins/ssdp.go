// Package plugins provides SSDP (Simple Service Discovery Protocol) service fingerprinting
package plugins

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
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

	parsed, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(response[:n])), nil)
	if err != nil {
		return nil, fmt.Errorf("invalid SSDP response: %w", err)
	}
	defer func() { _ = parsed.Body.Close() }()
	if parsed.Proto != "HTTP/1.1" || parsed.StatusCode != http.StatusOK ||
		strings.TrimSpace(parsed.Header.Get("ST")) == "" ||
		strings.TrimSpace(parsed.Header.Get("USN")) == "" ||
		strings.TrimSpace(parsed.Header.Get("LOCATION")) == "" {
		return nil, fmt.Errorf("not an SSDP response")
	}

	// Build typed metadata
	metadata := &protocol.SsdpServerInfo{}
	var version *string

	status := parsed.Proto + " " + parsed.Status
	metadata.Status = &status
	for name, field := range map[string]**string{
		"SERVER": &metadata.Server, "LOCATION": &metadata.Location,
		"ST": &metadata.ServiceType, "USN": &metadata.Usn,
		"CACHE-CONTROL": &metadata.CacheControl,
	} {
		if value := parsed.Header.Get(name); value != "" {
			*field = &value
		}
	}
	version = metadata.Server

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeSsdp,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Ssdp: metadata},
	}

	return result, nil
}
