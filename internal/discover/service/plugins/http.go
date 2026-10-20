// Package plugins provides HTTP service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"
	"net/http"

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

	// Try HTTPS first, then HTTP
	protocols := []struct {
		scheme string
		isTLS  bool
	}{
		{"https", true},
		{"http", false},
	}

	for _, proto := range protocols {
		p := newProductHTTP(ip, port, host, timeout, proto.isTLS)
		u := p.base
		u.Path = "/"
		req, err := http.NewRequestWithContext(timeoutCtx, "HEAD", u.String(), nil)
		if err != nil {
			p.transport.CloseIdleConnections()
			continue
		}
		if userAgent := helpers.HTTPUserAgent(ctx, ""); userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
		// Fingerprint the requested socket, not a redirect's destination.
		resp, err := p.transport.RoundTrip(req)
		p.transport.CloseIdleConnections()
		if err != nil {
			continue // Try next protocol
		}
		_ = resp.Body.Close()

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
