// Package plugins provides WinRM service fingerprinting
package plugins

import (
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

type WinRMFingerprinter struct{}

func (WinRMFingerprinter) Name() string { return "winrm" }

func (WinRMFingerprinter) DefaultPorts() []int { return []int{5985, 5986} }

func (WinRMFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Try non-TLS first, then TLS
	result, _ := detectWinRMWithScheme(ctx, ip, port, host, timeout, false)
	if result != nil {
		return result, nil
	}

	// Try TLS
	return detectWinRMWithScheme(ctx, ip, port, host, timeout, true)
}

func detectWinRMWithScheme(ctx context.Context, ip net.IP, port int, host string, timeout int, useTLS bool) (*discoverfern.ServiceDetails, error) {
	scheme := "http"
	transport := common.TransportTypeTcp
	if useTLS {
		scheme = "https"
		transport = common.TransportTypeTcptls
	}

	url := fmt.Sprintf("%s://%s/wsman", scheme, net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))

	// Create WinRM Identify request
	requestBody := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Header/>
  <s:Body>
    <wsmid:Identify/>
  </s:Body>
</s:Envelope>`

	// Create HTTP client
	client := &http.Client{
		Timeout: helpers.Timeout(timeout),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(requestBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("User-Agent", "networkscan")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Check for WinRM Server header first - this is a strong indicator even with 404
	serverHeader := resp.Header.Get("Server")
	hasWinRMServer := serverHeader == "Microsoft-HTTPAPI/2.0"

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	bodyStr := string(body)

	// Check for WinRM/WS-Management indicators in body
	hasWinRMBodyIndicator := strings.Contains(bodyStr, "wsman") ||
		strings.Contains(bodyStr, "IdentifyResponse") ||
		strings.Contains(bodyStr, "ProductVendor") ||
		strings.Contains(bodyStr, "ProductVersion") ||
		strings.Contains(bodyStr, "ProtocolVersion")

	// WinRM detection logic:
	// 1. If we have WinRM server header, accept any status code (including 404)
	// 2. If status is success (< 400) and body has WinRM indicators, accept it
	// 3. Otherwise, not WinRM
	if !hasWinRMServer {
		// No WinRM server header, so check if it's a success response with WinRM body
		if resp.StatusCode >= 400 {
			return nil, nil // Error status and no WinRM header
		}
		if !hasWinRMBodyIndicator {
			return nil, nil // Success but no WinRM body indicators
		}
	}

	statusCode := fmt.Sprintf("%d", resp.StatusCode)

	var server *string
	if serverHeader != "" {
		server = &serverHeader
	}

	var productVersion *string
	if strings.Contains(bodyStr, "ProductVersion") {
		start := strings.Index(bodyStr, "<wsmid:ProductVersion>")
		if start != -1 {
			start += len("<wsmid:ProductVersion>")
			end := strings.Index(bodyStr[start:], "</wsmid:ProductVersion>")
			if end != -1 {
				pv := bodyStr[start : start+end]
				productVersion = &pv
			}
		}
	}

	var protocolVersion *string
	if strings.Contains(bodyStr, "ProtocolVersion") {
		start := strings.Index(bodyStr, "<wsmid:ProtocolVersion>")
		if start != -1 {
			start += len("<wsmid:ProtocolVersion>")
			end := strings.Index(bodyStr[start:], "</wsmid:ProtocolVersion>")
			if end != -1 {
				pv := bodyStr[start : start+end]
				protocolVersion = &pv
			}
		}
	}

	metadata := &protocol.WinrmServerInfo{
		Server:          server,
		StatusCode:      &statusCode,
		Scheme:          &scheme,
		ProductVersion:  productVersion,
		ProtocolVersion: protocolVersion,
	}

	version := server
	if version == nil && productVersion != nil {
		version = productVersion
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       useTLS,
		Transport: transport,
		Protocol:  common.ProtocolTypeWinrm,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Winrm: metadata},
	}

	return result, nil
}
