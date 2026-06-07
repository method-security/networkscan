// Package plugins provides HTTP service fingerprinting
package plugins

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type HTTPFingerprinter struct{}

func (HTTPFingerprinter) Name() string { return "http" }

func (HTTPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Create a context using the scanner timeout.
	timeoutCtx, cancel := serviceContext(ctx, timeout)
	defer cancel()

	// Use proper HTTP client with the scanner timeout.
	client := &http.Client{
		Timeout: serviceTimeout(timeout),
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
		req, err := http.NewRequestWithContext(timeoutCtx, "HEAD", url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue // Try next protocol
		}
		_ = resp.Body.Close()

		// Extract server info
		server := resp.Header.Get("Server")
		if server == "" {
			server = "HTTP Server" // Default if no server header
		}

		// Use HTTPS protocol when TLS is detected, otherwise HTTP
		protocolName := "HTTP"
		if proto.isTLS {
			protocolName = "HTTPS"
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
			Tls:       proto.isTLS,
			Version:   &server,
			Transport: common.TransportTypeTcp,
			Protocol: func() common.ProtocolType {
				if protocol, err := common.NewProtocolTypeFromString(strings.ToUpper(protocolName)); err == nil {
					return protocol
				}
				return common.ProtocolTypeUnknown
			}(),
			Metadata: &discoverfern.ServiceMetadata{Generic: &discoverfern.GenericServiceMetadata{
				Metadata: metadata,
			}},
		}, nil
	}

	return nil, fmt.Errorf("no HTTP service detected")
}
