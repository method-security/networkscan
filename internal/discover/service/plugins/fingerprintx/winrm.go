// Package fingerprintx provides WinRM service fingerprinting for fingerprintx
package fingerprintx

import (
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

type WinRMMetadata struct {
	Server          string `json:"server,omitempty"`
	StatusCode      int    `json:"status_code"`
	Scheme          string `json:"scheme"`
	ProductVersion  string `json:"product_version,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
}

func (WinRMMetadata) Type() string { return "winrm" }

/* ---------- plugins ---------- */

type WinRMPlugin struct{}
type WinRMTLSPlugin struct{}

func (p *WinRMPlugin) Name() string    { return "winrm" }
func (p *WinRMTLSPlugin) Name() string { return "winrm_tls" }

func (p *WinRMPlugin) Type() plugins.Protocol    { return plugins.TCP }
func (p *WinRMTLSPlugin) Type() plugins.Protocol { return plugins.TCPTLS }

func (p *WinRMPlugin) PortPriority(port uint16) bool    { return port == 5985 }
func (p *WinRMTLSPlugin) PortPriority(port uint16) bool { return port == 5986 }

func (p *WinRMPlugin) Priority() int    { return 90 }
func (p *WinRMTLSPlugin) Priority() int { return 91 }

func init() {
	plugins.RegisterPlugin(&WinRMPlugin{})
	plugins.RegisterPlugin(&WinRMTLSPlugin{})
}

/* ---------- runtime ---------- */

func (p *WinRMPlugin) Run(conn net.Conn, t time.Duration, tgt plugins.Target) (*plugins.Service, error) {
	return detectWinRM(conn, tgt, t, false)
}

func (p *WinRMTLSPlugin) Run(conn net.Conn, t time.Duration, tgt plugins.Target) (*plugins.Service, error) {
	return detectWinRM(conn, tgt, t, true)
}

/* ---------- detector ---------- */

func detectWinRM(conn net.Conn, tgt plugins.Target, timeout time.Duration, useTLS bool) (*plugins.Service, error) {
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

	url := fmt.Sprintf("%s://%s/wsman", scheme, tgt.Address.String())

	// Create WinRM Identify request
	requestBody := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Header/>
  <s:Body>
    <wsmid:Identify/>
  </s:Body>
</s:Envelope>`

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

	req, err := http.NewRequest("POST", url, strings.NewReader(requestBody))
	if err != nil {
		return nil, nil
	}

	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("User-Agent", "networkscan")

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

	bodyStr := string(body)

	// Check for WinRM/WS-Management indicators
	if !(strings.Contains(bodyStr, "wsman") ||
		strings.Contains(bodyStr, "IdentifyResponse") ||
		strings.Contains(bodyStr, "ProductVendor") ||
		resp.Header.Get("Server") == "Microsoft-HTTPAPI/2.0") {
		return nil, nil
	}

	meta := WinRMMetadata{
		StatusCode: resp.StatusCode,
		Scheme:     scheme,
	}

	if server := resp.Header.Get("Server"); server != "" {
		meta.Server = server
	}

	// Extract product version
	if strings.Contains(bodyStr, "ProductVersion") {
		start := strings.Index(bodyStr, "<wsmid:ProductVersion>")
		if start != -1 {
			start += len("<wsmid:ProductVersion>")
			end := strings.Index(bodyStr[start:], "</wsmid:ProductVersion>")
			if end != -1 {
				meta.ProductVersion = bodyStr[start : start+end]
			}
		}
	}

	// Extract protocol version
	if strings.Contains(bodyStr, "ProtocolVersion") {
		start := strings.Index(bodyStr, "<wsmid:ProtocolVersion>")
		if start != -1 {
			start += len("<wsmid:ProtocolVersion>")
			end := strings.Index(bodyStr[start:], "</wsmid:ProtocolVersion>")
			if end != -1 {
				meta.ProtocolVersion = bodyStr[start : start+end]
			}
		}
	}

	transport := plugins.TCP
	if useTLS {
		transport = plugins.TCPTLS
	}

	return plugins.CreateServiceFrom(tgt, meta, useTLS, "", transport), nil
}
