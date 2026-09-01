// Package plugins provides IPP service fingerprinting
package plugins

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type IPPFingerprinter struct{}

func (IPPFingerprinter) Name() string { return "ipp" }

func (IPPFingerprinter) DefaultPorts() []int { return []int{631} }

func (IPPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Try non-TLS first, then TLS
	result, _ := detectIPPWithScheme(ctx, ip, port, host, timeout, false)
	if result != nil {
		return result, nil
	}

	// Try TLS
	return detectIPPWithScheme(ctx, ip, port, host, timeout, true)
}

func detectIPPWithScheme(ctx context.Context, ip net.IP, port int, host string, timeout int, useTLS bool) (*discoverfern.ServiceDetails, error) {
	scheme := "http"
	transport := common.TransportTypeTcp
	if useTLS {
		scheme = "https"
		transport = common.TransportTypeTcptls
	}

	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))

	// IPP Get-Printer-Attributes request
	ippGetAttributesRequest := []byte{
		0x01, 0x01, // IPP version 1.1
		0x00, 0x0B, // Operation: Get-Printer-Attributes
		0x00, 0x00, 0x00, 0x01, // Request ID
		0x01,       // Begin attribute group tag (operation-attributes-tag)
		0x47,       // charset type
		0x00, 0x12, // name length
		'a', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 's', '-', 'c', 'h', 'a', 'r', 's', 'e', 't',
		0x00, 0x05, // value length
		'u', 't', 'f', '-', '8',
		0x48,       // natural-language type
		0x00, 0x1b, // name length
		'a', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 's', '-', 'n', 'a', 't', 'u', 'r', 'a', 'l', '-', 'l', 'a', 'n', 'g', 'u', 'a', 'g', 'e',
		0x00, 0x05, // value length
		'e', 'n', '-', 'u', 's',
		0x45,       // uri type
		0x00, 0x0b, // name length
		'p', 'r', 'i', 'n', 't', 'e', 'r', '-', 'u', 'r', 'i',
		0x00, 0x03, // value length
		'i', 'p', 'p',
		0x03, // End of attributes
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: helpers.Timeout(timeout),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(ippGetAttributesRequest))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/ipp")
	req.Header.Set("User-Agent", "networkscan-ipp")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Verify it's actually IPP
	serverHeader := resp.Header.Get("Server")
	hasIPPHeader := strings.Contains(strings.ToLower(serverHeader), "ipp") ||
		strings.Contains(strings.ToLower(serverHeader), "cups")

	// Check if response is valid IPP binary (starts with version bytes)
	isIPPBinary := len(body) >= 4 &&
		((body[0] == 0x01 && body[1] == 0x01) || // IPP 1.1
			(body[0] == 0x02 && body[1] == 0x00)) // IPP 2.0

	// Accept if EITHER we have IPP header AND binary response, OR just valid IPP binary
	if !isIPPBinary && !hasIPPHeader {
		return nil, nil
	}

	// If we have header but not binary, at least verify it's not a spoofed header
	if hasIPPHeader && !isIPPBinary {
		contentType := resp.Header.Get("Content-Type")
		if !strings.Contains(strings.ToLower(contentType), "ipp") &&
			!strings.Contains(strings.ToLower(serverHeader), "cups/") {
			// Server header says "IPP" but no IPP content-type and no CUPS version - likely spoofed
			return nil, nil
		}
	}

	var server *string
	if serverHeader != "" {
		server = &serverHeader
	}

	httpStatus := fmt.Sprintf("%d", resp.StatusCode)

	var statusCode *string
	var version *string
	if isIPPBinary {
		code := fmt.Sprintf("0x%04x", (uint16(body[2])<<8)|uint16(body[3]))
		statusCode = &code

		// Extract IPP version from response bytes
		majorVer := body[0]
		minorVer := body[1]
		versionStr := fmt.Sprintf("%d.%d", majorVer, minorVer)
		version = &versionStr
	}

	// Fallback to server header if no version extracted from binary
	if version == nil {
		version = server
	}

	metadata := &protocol.IppServerInfo{
		Server:     server,
		StatusCode: statusCode,
		HttpStatus: &httpStatus,
		Scheme:     &scheme,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       boolPtr(useTLS),
		Transport: transport,
		Protocol:  common.ProtocolTypeIpp,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Ipp: metadata},
	}

	return result, nil
}
