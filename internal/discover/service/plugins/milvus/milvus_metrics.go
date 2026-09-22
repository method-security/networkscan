// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package milvus

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type MilvusMetricsPlugin struct{}

const MILVUS_METRICS = "milvus-metrics"

// DetectMilvusMetrics performs Milvus detection via Prometheus metrics endpoint.
//
// Parameters:
//   - conn: Existing network connection to reuse
//   - target: Target information (host for Host header)
//   - timeout: HTTP request timeout duration
//
// Returns:
//   - string: Version string if successful, empty string otherwise
//   - bool: true if Milvus metrics detected
//   - error: Error details if detection failed
func DetectMilvusMetrics(conn net.Conn, target helpers.Endpoint, timeout time.Duration) (string, bool, error) {

	metricsURL := fmt.Sprintf("http://%s/metrics", conn.RemoteAddr().String())

	req, err := http.NewRequest("GET", metricsURL, nil)
	if err != nil {
		return "", false, err
	}

	if target.Host != "" {
		req.Host = target.Host
	}

	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("metrics endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", false, err
	}

	bodyStr := string(body)

	if !strings.Contains(bodyStr, "milvus_build_info") {
		return "", false, nil
	}

	version := extractVersionFromMetrics(bodyStr)

	return version, true, nil
}

// extractVersionFromMetrics extracts version from Prometheus metrics response.
//
// Looks for milvus_build_info metric and parses the version label.
//
// Parameters:
//   - metrics: Prometheus metrics response body
//
// Returns:
//   - string: Extracted version string, or empty if not found
func extractVersionFromMetrics(metrics string) string {

	versionRegex := regexp.MustCompile(`milvus_build_info\{[^}]*version="v?([^"]+)"`)
	matches := versionRegex.FindStringSubmatch(metrics)
	if len(matches) >= 2 {
		version := matches[1]
		return strings.TrimPrefix(version, "v")
	}

	return ""
}
func (p *MilvusMetricsPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	version, detected, err := DetectMilvusMetrics(conn, target, timeout)
	if !detected {
		return nil, err
	}

	payload := ServiceMilvusMetrics{}

	cpe := buildMilvusCPE(version)
	payload.CPEs = []string{cpe}

	return helpers.MetadataResult(target, payload, false, version, common.TransportTypeTcp), nil
}
func (p *MilvusMetricsPlugin) PortPriority(port uint16) bool {
	return port == 9091
}
func (p *MilvusMetricsPlugin) Name() string {
	return MILVUS_METRICS
}
func (p *MilvusMetricsPlugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *MilvusMetricsPlugin) Priority() int {
	return 51
}

var defaultMilvusMetricsPluginPorts = helpers.Ports((&MilvusMetricsPlugin{}).PortPriority)

func (p *MilvusMetricsPlugin) DefaultPorts() []int { return defaultMilvusMetricsPluginPorts }
func (p *MilvusMetricsPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
