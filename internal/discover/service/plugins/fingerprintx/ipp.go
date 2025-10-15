// Package fingerprintx provides IPP service fingerprinting for fingerprintx
package fingerprintx

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	plugins "github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

/* ---------- metadata ---------- */

type IPPMetadata struct {
	Version    string `json:"version"`
	StatusCode string `json:"status_code"`
	HTTPStatus int    `json:"http_status"`
	Scheme     string `json:"scheme"`
}

func (IPPMetadata) Type() string { return "ipp" }

/* ---------- plugins ---------- */

type IPPPlugin struct{}
type IPPTLSPlugin struct{}

func (p *IPPPlugin) Name() string    { return "ipp" }
func (p *IPPTLSPlugin) Name() string { return "ipp_tls" }

func (p *IPPPlugin) Type() plugins.Protocol    { return plugins.TCP }
func (p *IPPTLSPlugin) Type() plugins.Protocol { return plugins.TCPTLS }

func (p *IPPPlugin) PortPriority(port uint16) bool    { return port == 631 }
func (p *IPPTLSPlugin) PortPriority(port uint16) bool { return port == 631 }

func (p *IPPPlugin) Priority() int    { return 150 } // Very high priority to run before HTTP
func (p *IPPTLSPlugin) Priority() int { return 150 } // Very high priority to run before HTTPS

func init() {
	plugins.RegisterPlugin(&IPPPlugin{})
	plugins.RegisterPlugin(&IPPTLSPlugin{})
}

/* ---------- runtime ---------- */

func (p *IPPPlugin) Run(conn net.Conn, t time.Duration, tgt plugins.Target) (*plugins.Service, error) {
	return detectIPP(conn, tgt, t, false)
}

func (p *IPPTLSPlugin) Run(conn net.Conn, t time.Duration, tgt plugins.Target) (*plugins.Service, error) {
	return detectIPP(conn, tgt, t, true)
}

/* ---------- detector ---------- */

// IPP Get-Printer-Attributes request
var ippGetAttributesRequest = []byte{
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

func detectIPP(conn net.Conn, tgt plugins.Target, timeout time.Duration, useTLS bool) (*plugins.Service, error) {
	scheme := "http"
	if useTLS {
		scheme = "https"
		tc := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         tgt.Host,
		})
		if err := tc.Handshake(); err != nil {
			return nil, nil
		}
		conn = tc
	}

	// IPP over HTTP - try root endpoint (CUPS typically responds to /)
	url := fmt.Sprintf("%s://%s/", scheme, tgt.Address.String())

	// Create HTTP client using the already-open connection
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(ippGetAttributesRequest))
	if err != nil {
		return nil, nil
	}

	req.Header.Set("Content-Type", "application/ipp")
	req.Header.Set("User-Agent", "networkscan-ipp")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil
	}

	// Verify it's actually IPP by checking BOTH:
	// 1. Server header contains IPP/CUPS indicators
	// 2. Response body is valid IPP binary format OR response headers indicate IPP

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
	// by checking Content-Type or other IPP-specific headers
	if hasIPPHeader && !isIPPBinary {
		contentType := resp.Header.Get("Content-Type")
		// CUPS/IPP servers typically return text/html, application/ipp, or other IPP-related content types
		// Accept if we have IPP/CUPS in server header (not just relying on header alone)
		if !strings.Contains(strings.ToLower(contentType), "ipp") &&
			!strings.Contains(strings.ToLower(serverHeader), "cups/") {
			// Server header says "IPP" but no IPP content-type and no CUPS version - likely spoofed
			return nil, nil
		}
	}

	meta := IPPMetadata{
		Version:    serverHeader, // e.g., "CUPS/2.3 IPP/2.1"
		HTTPStatus: resp.StatusCode,
		Scheme:     scheme,
	}

	// Extract IPP status code from binary response if available
	if isIPPBinary {
		statusCode := (uint16(body[2]) << 8) | uint16(body[3])
		meta.StatusCode = fmt.Sprintf("0x%04x", statusCode)
	}

	transport := plugins.TCP
	if useTLS {
		transport = plugins.TCPTLS
	}

	return plugins.CreateServiceFrom(tgt, meta, useTLS, "", transport), nil
}
