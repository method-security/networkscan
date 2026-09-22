// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package pinecone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

// PINECONEPlugin detects Pinecone Vector Database instances.
//
// Detection Strategy:
// Pinecone is a managed vector database (SaaS) that runs on HTTPS (port 443).
// When an unauthenticated request is sent to a Pinecone endpoint, the service
// returns a 401 Unauthorized response with Pinecone-specific headers:
//   - x-pinecone-api-version (PRIMARY marker - unique to Pinecone)
//   - x-pinecone-auth-rejected-reason (SECONDARY marker)
//
// This approach is similar to MySQL error packet detection - the service
// identifies itself in rejection responses without requiring valid credentials.
//
// Version Detection:
// The x-pinecone-api-version header contains the API version (e.g., "2025-01"),
// not the internal Pinecone service version. Since Pinecone is closed-source SaaS,
// the internal version cannot be determined. Therefore, the CPE uses a wildcard
// version: cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*
type PINECONEPlugin struct{}

const (
	PROTOCOL_NAME = "pinecone"
	DEFAULT_PORT  = 443
	USERAGENT     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

	// Header constants for detection
	HEADER_API_VERSION   = "X-Pinecone-Api-Version"
	HEADER_AUTH_REJECTED = "X-Pinecone-Auth-Rejected-Reason"
)

// Run performs Pinecone detection via 401 response header analysis.
//
// Phase 1: Detection
//   - Send unauthenticated HTTPS GET request
//   - Receive 401 Unauthorized response
//   - Check for x-pinecone-api-version header (PRIMARY)
//   - Check for x-pinecone-auth-rejected-reason header (SECONDARY fallback)
//
// Phase 2: Enrichment
//   - Extract API version from header value
//   - Store as metadata (not used in CPE due to API vs service version distinction)
//
// Returns:
//   - *discover.ServiceDetails with Pinecone detection if headers present
//   - nil if not detected
//   - error on request failures (connection issues, timeouts)
func (p *PINECONEPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s", conn.RemoteAddr().String()), nil)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, nil
		}
		return nil, &utils.RequestError{Message: err.Error()}
	}

	if target.Host != "" {
		req.Host = target.Host
	}

	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},

		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req.Header.Set("User-Agent", USERAGENT)

	resp, err := client.Do(req)
	if err != nil {
		return nil, &utils.RequestError{Message: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()

	apiVersion := resp.Header.Get(HEADER_API_VERSION)
	authRejected := resp.Header.Get(HEADER_AUTH_REJECTED)

	if apiVersion != "" {
		return p.buildDetectionResult(target, resp, apiVersion, "high")
	}

	if authRejected != "" {
		return p.buildDetectionResult(target, resp, "", "medium")
	}

	return nil, nil
}

// buildDetectionResult constructs the Service object for detected Pinecone instances.
//
// CPE Format: cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*
//   - Version field is wildcard (*) because internal service version is unavailable
//   - Only API version (from header) is known, which represents API contract not service version
func (p *PINECONEPlugin) buildDetectionResult(
	target helpers.Endpoint,
	resp *http.Response,
	apiVersion string,
	confidence string,
) (*discover.ServiceDetails, error) {

	cpe := "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*"

	payload := ServicePinecone{
		CPEs: []string{cpe},

		APIVersion: apiVersion,
	}

	return helpers.MetadataResult(target, payload, true, "", common.TransportTypeTcptls), nil
}

// PortPriority returns true for port 443 (Pinecone's default HTTPS port).
func (p *PINECONEPlugin) PortPriority(port uint16) bool {
	return port == DEFAULT_PORT
}

// Name returns the protocol identifier.
func (p *PINECONEPlugin) Name() string {
	return PROTOCOL_NAME
}

// Type returns TCPTLS since Pinecone uses HTTPS.
func (p *PINECONEPlugin) Type() common.TransportType {
	return common.TransportTypeTcptls
}

// Priority returns 50, which runs after SSH/databases but before generic HTTPS.
//
// Priority ordering ensures:
//   - Pinecone-specific detection (50) runs before generic HTTPS (1)
//   - Database protocols run first (MongoDB -1, MySQL 0, etc.)
//   - Generic HTTP/HTTPS run last as catch-all
func (p *PINECONEPlugin) Priority() int {
	return 50
}

var defaultPINECONEPluginPorts = helpers.Ports((&PINECONEPlugin{}).PortPriority)

func (p *PINECONEPlugin) DefaultPorts() []int { return defaultPINECONEPluginPorts }
func (p *PINECONEPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
