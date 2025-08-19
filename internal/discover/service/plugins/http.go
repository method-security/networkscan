// Package plugins provides HTTP service fingerprinting
package plugins

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type HTTPFingerprinter struct{}

func (HTTPFingerprinter) Name() string { return "http" }

func (HTTPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Create a context with 10-second timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Use proper HTTP client with 10-second timeout
	client := &http.Client{
		Timeout: 10 * time.Second, // Fixed 10-second timeout
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
		url := fmt.Sprintf("%s://%s:%d/", proto.scheme, ip, port)
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
			Metadata: map[string]string{
				"status": fmt.Sprintf("%d %s", resp.StatusCode, resp.Status),
				"server": server,
				"scheme": proto.scheme,
			},
		}, nil
	}

	return nil, fmt.Errorf("no HTTP service detected")
}
