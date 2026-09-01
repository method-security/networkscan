// Package plugins provides WinRM service fingerprinting
package plugins

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
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

	serverHeader := resp.Header.Get("Server")

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	metadata, hasWSManResponse := parseWinRMBody(body)
	hasWSManAuthChallenge := hasWinRMAuthChallenge(resp) && hasWinRMPostOnlyEndpoint(ctx, client, scheme, ip, port)

	// Microsoft-HTTPAPI/2.0 is emitted by HTTP.sys for many Microsoft services,
	// so the Server header alone is not enough to identify WinRM. Require a
	// WS-Man SOAP response or the standard unauthenticated WinRM pattern:
	// GET /wsman is method-rejected and POST /wsman returns an auth challenge.
	if !hasWSManResponse && !hasWSManAuthChallenge {
		return nil, nil
	}

	statusCode := fmt.Sprintf("%d", resp.StatusCode)

	var server *string
	if serverHeader != "" {
		server = &serverHeader
	}

	metadata.Server = server
	metadata.StatusCode = &statusCode
	metadata.Scheme = &scheme
	if authSchemes := winRMAuthSchemes(resp.Header); len(authSchemes) > 0 {
		metadata.AuthSchemes = authSchemes
	}

	version := server
	if version == nil && metadata.ProductVersion != nil {
		version = metadata.ProductVersion
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       boolPtr(useTLS),
		Transport: transport,
		Protocol:  common.ProtocolTypeWinrm,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Winrm: metadata},
	}

	return result, nil
}

func parseWinRMBody(body []byte) (*protocol.WinrmServerInfo, bool) {
	info := &protocol.WinrmServerInfo{}
	hasIndicator := false
	decoder := xml.NewDecoder(bytes.NewReader(body))

	var captureName string
	var captureValue strings.Builder

	for {
		token, err := decoder.Token()
		if err != nil {
			return info, hasIndicator
		}

		switch typed := token.(type) {
		case xml.StartElement:
			if !isWSManNamespace(typed.Name.Space) {
				continue
			}

			localName := strings.ToLower(typed.Name.Local)
			switch localName {
			case "identifyresponse", "productvendor", "productversion", "protocolversion", "wsmanfault":
				hasIndicator = true
			}

			switch localName {
			case "productversion", "protocolversion":
				captureName = localName
				captureValue.Reset()
			}
		case xml.CharData:
			if captureName != "" {
				captureValue.Write([]byte(typed))
			}
		case xml.EndElement:
			if captureName == "" || strings.ToLower(typed.Name.Local) != captureName {
				continue
			}

			value := strings.TrimSpace(captureValue.String())
			if value != "" {
				switch captureName {
				case "productversion":
					info.ProductVersion = winRMStringPtr(value)
				case "protocolversion":
					info.ProtocolVersion = winRMStringPtr(value)
				}
			}

			captureName = ""
			captureValue.Reset()
		}
	}
}

func isWSManNamespace(namespace string) bool {
	return strings.Contains(strings.ToLower(namespace), "/wsman/")
}

func hasWinRMAuthChallenge(resp *http.Response) bool {
	if resp.StatusCode != http.StatusUnauthorized || !strings.EqualFold(resp.Header.Get("Server"), "Microsoft-HTTPAPI/2.0") {
		return false
	}

	for _, challenge := range resp.Header.Values("WWW-Authenticate") {
		lowerChallenge := strings.ToLower(challenge)
		if strings.HasPrefix(lowerChallenge, "negotiate") ||
			strings.HasPrefix(lowerChallenge, "kerberos") ||
			strings.HasPrefix(lowerChallenge, "credssp") ||
			strings.Contains(lowerChallenge, `basic realm="wsman"`) {
			return true
		}
	}

	return false
}

func hasWinRMPostOnlyEndpoint(ctx context.Context, client *http.Client, scheme string, ip net.IP, port int) bool {
	url := fmt.Sprintf("%s://%s/wsman", scheme, net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusMethodNotAllowed {
		return false
	}

	for _, allowedMethod := range strings.Split(resp.Header.Get("Allow"), ",") {
		if strings.EqualFold(strings.TrimSpace(allowedMethod), http.MethodPost) {
			return true
		}
	}

	return false
}

func winRMAuthSchemes(header http.Header) []string {
	var schemes []string
	seen := make(map[string]struct{})

	for _, challenge := range header.Values("WWW-Authenticate") {
		fields := strings.Fields(challenge)
		if len(fields) == 0 {
			continue
		}

		scheme := fields[0]
		if _, ok := seen[strings.ToLower(scheme)]; ok {
			continue
		}

		seen[strings.ToLower(scheme)] = struct{}{}
		schemes = append(schemes, scheme)
	}

	return schemes
}

func winRMStringPtr(value string) *string {
	return &value
}
