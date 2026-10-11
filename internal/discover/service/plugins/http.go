// Package plugins provides HTTP service fingerprinting
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
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type HTTPFingerprinter struct{}

func (HTTPFingerprinter) Name() string { return "http" }

func (HTTPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Create a context using the scanner timeout.
	timeoutCtx, cancel := helpers.Context(ctx, timeout)
	defer cancel()

	// Use proper HTTP client with the scanner timeout.
	client := &http.Client{
		Timeout: helpers.Timeout(timeout),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // For HTTPS detection
		},
	}

	// Try HTTPS first, then HTTP
	protocols := []struct {
		scheme string
		isTLS  bool
	}{
		{"https", true},
		{"http", false},
	}

	for _, proto := range protocols {
		// Use net.JoinHostPort to properly format IPv6 addresses with brackets
		hostPort := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
		url := fmt.Sprintf("%s://%s/", proto.scheme, hostPort)
		req, err := http.NewRequestWithContext(timeoutCtx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue // Try next protocol
		}
		// Read enough body to catch common CDN/fronting error pages.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		_ = resp.Body.Close()
		if isHTTPFrontingError(resp.StatusCode, body) {
			continue
		}

		// Extract server info
		server := resp.Header.Get("Server")
		if server == "" {
			server = "HTTP Server" // Default if no server header
		}

		protocol := common.ProtocolTypeHttp
		if proto.isTLS {
			protocol = common.ProtocolTypeHttps
		}

		// Build generic metadata map
		metadata := map[string]string{
			"status":     fmt.Sprintf("%d %s", resp.StatusCode, resp.Status),
			"server":     server,
			"scheme":     proto.scheme,
			"statusCode": fmt.Sprintf("%d", resp.StatusCode),
		}

		return &discoverfern.ServiceDetails{
			Host:      host,
			Ip:        ip.String(),
			Port:      port,
			Tls:       helpers.BoolPtr(proto.isTLS),
			Version:   &server,
			Transport: common.TransportTypeTcp,
			Protocol:  protocol,
			Metadata: &discoverfern.ServiceMetadata{Generic: &discoverfern.GenericServiceMetadata{
				Metadata: metadata,
			}},
		}, nil
	}

	return nil, fmt.Errorf("no HTTP service detected")
}

func isHTTPFrontingError(statusCode int, body []byte) bool {

	lowerBody := strings.ToLower(string(body))
	for _, marker := range []string{
		"400 bad request",
		"http request to a https server",
		"http request to an https server",
		"plain http request was sent to https port",
		"speaking plain http to an ssl-enabled server port",
	} {
		if strings.Contains(lowerBody, marker) {
			return true
		}
	}
	return false
}
