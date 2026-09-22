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

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

type MilvusPlugin struct{}

const MILVUS = "milvus"

// milvusMetadata holds enriched metadata extracted from Milvus responses
type milvusMetadata struct {
	Version string // Milvus version string (e.g., "2.6.7")
}

// tryGetVersionViaGRPC attempts to retrieve Milvus version using gRPC GetVersion RPC.
//
// This function calls the GetVersion RPC directly without using gRPC reflection.
// The response is parsed to extract the version string.
//
// Parameters:
//   - target: Network address (e.g., "localhost:19530")
//   - timeout: RPC timeout duration
//
// Returns:
//   - string: Version string if successful, empty string otherwise
//   - bool: true if Milvus detected (even if version extraction fails)
//   - error: Error details if detection failed
func tryGetVersionViaGRPC(ctx context.Context, target string, timeout time.Duration) (string, bool, error) {

	conn, err := utils.GRPCDialWithTimeout(ctx, target, timeout)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = conn.Close() }()

	method := "/milvus.proto.milvus.MilvusService/GetVersion"
	request := []byte{}

	response, err := utils.GRPCInvokeUnary(ctx, conn, method, request, timeout)
	if err != nil {

		return "", false, err
	}

	version := parseVersionFromProtobuf(response)

	return version, true, nil
}

// parseVersionFromProtobuf extracts version string from a protobuf message.
//
// This is a simplified parser that looks for the version string pattern in the
// raw protobuf bytes. It's less robust than full protobuf parsing but sufficient
// for fingerprinting without importing heavy proto dependencies.
//
// Protobuf string encoding: field_number(varint) + length(varint) + string_bytes
// For GetVersionResponse, version is typically field 2 (wire type 2 = length-delimited)
//
// Parameters:
//   - data: Raw protobuf response bytes
//
// Returns:
//   - string: Extracted version string, or empty if not found
func parseVersionFromProtobuf(data []byte) string {

	versionRegex := regexp.MustCompile(`v?([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?)`)

	dataStr := string(data)
	matches := versionRegex.FindStringSubmatch(dataStr)
	if len(matches) >= 2 {

		version := matches[1]
		return strings.TrimPrefix(version, "v")
	}

	return ""
}

// tryGetVersionViaHTTPREST attempts to detect Milvus using HTTP REST API on same port.
//
// Milvus v2.3.x+ supports HTTP REST API on the same port as gRPC (19530).
// This is a secondary detection method when gRPC fails or is unavailable.
//
// IMPORTANT: This function reuses the provided connection via custom HTTP transport
// to avoid creating new connections, following the same pattern as MilvusMetricsPlugin.
//
// Parameters:
//   - conn: Existing network connection to reuse
//   - target: Target information (host for Host header)
//   - timeout: HTTP request timeout duration
//
// Returns:
//   - string: Version string if successful, empty string otherwise
//   - bool: true if Milvus detected via HTTP REST API
//   - error: Error details if detection failed
func tryGetVersionViaHTTPREST(conn net.Conn, target probe.Target, timeout time.Duration) (string, bool, error) {

	url := fmt.Sprintf("http://%s/v1/vector/collections", conn.RemoteAddr().String())

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", false, err
	}

	if target.Host != "" {
		req.Host = target.Host
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")

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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", false, err
	}

	bodyStr := string(body)

	isMilvusResponse := false

	if strings.Contains(bodyStr, "milvus") ||
		strings.Contains(bodyStr, "Milvus") ||
		strings.Contains(strings.ToLower(resp.Header.Get("Server")), "milvus") {
		isMilvusResponse = true
	}

	if resp.StatusCode == http.StatusOK &&
		strings.Contains(resp.Header.Get("Content-Type"), "application/json") &&
		(strings.Contains(bodyStr, `"code":`) && strings.Contains(bodyStr, `"data":`)) {
		isMilvusResponse = true
	}

	if !isMilvusResponse {
		return "", false, nil
	}

	version := extractVersionFromHTTPResponse(bodyStr, resp.Header)
	return version, true, nil
}

// extractVersionFromHTTPResponse attempts to extract version from HTTP response.
//
// Looks for version patterns in response body or headers.
//
// Parameters:
//   - body: HTTP response body as string
//   - headers: HTTP response headers
//
// Returns:
//   - string: Extracted version string, or empty if not found
func extractVersionFromHTTPResponse(body string, headers http.Header) string {

	versionRegex := regexp.MustCompile(`"version"\s*:\s*"v?([0-9]+\.[0-9]+\.[0-9]+[^"]*)"`)
	matches := versionRegex.FindStringSubmatch(body)
	if len(matches) >= 2 {
		return strings.TrimPrefix(matches[1], "v")
	}

	if serverHeader := headers.Get("Server"); serverHeader != "" {
		versionRegex := regexp.MustCompile(`v?([0-9]+\.[0-9]+\.[0-9]+)`)
		matches := versionRegex.FindStringSubmatch(serverHeader)
		if len(matches) >= 2 {
			return strings.TrimPrefix(matches[1], "v")
		}
	}

	return ""
}

// DetectMilvus performs Milvus fingerprinting using gRPC and HTTP REST API.
//
// Detection Strategy:
//  1. PRIMARY: Try gRPC GetVersion RPC on target port (19530)
//  2. SECONDARY: Try HTTP REST API on same port (Milvus v2.3.x+ feature)
//     Uses provided connection to avoid creating new connections
//
// Parameters:
//   - conn: Network connection (reused for HTTP REST API detection)
//   - timeout: Detection timeout duration
//   - target: Target information
//
// Returns:
//   - milvusMetadata: Extracted metadata (version)
//   - bool: true if Milvus detected
//   - error: Error details if detection failed
func DetectMilvus(conn net.Conn, timeout time.Duration, target probe.Target) (milvusMetadata, bool, error) {
	metadata := milvusMetadata{}

	targetAddr := target.Address.String()

	version, detected, _ := tryGetVersionViaHTTPREST(conn, target, timeout)
	if detected {
		metadata.Version = version
		return metadata, true, nil
	}

	version, detected, err := tryGetVersionViaGRPC(target.Context, targetAddr, timeout)
	if detected {
		metadata.Version = version
		return metadata, true, nil
	}

	return metadata, false, err
}

// buildMilvusCPE constructs a CPE (Common Platform Enumeration) string for Milvus.
// CPE format: cpe:2.3:a:milvus:milvus:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to match other plugins'
// behavior and enable asset inventory use cases.
//
// Parameters:
//   - version: Milvus version string (e.g., "2.6.7"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" for unknown version
func buildMilvusCPE(version string) string {

	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:milvus:milvus:%s:*:*:*:*:*:*:*", version)
}
func (p *MilvusPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	metadata, detected, err := DetectMilvus(conn, timeout, target)
	if !detected {
		return nil, err
	}

	payload := probe.ServiceMilvus{}

	cpe := buildMilvusCPE(metadata.Version)
	payload.CPEs = []string{cpe}

	return probe.Result(target, payload, false, metadata.Version, probe.TCP), nil
}
func (p *MilvusPlugin) PortPriority(port uint16) bool {
	return port == 19530
}
func (p *MilvusPlugin) Name() string {
	return MILVUS
}
func (p *MilvusPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *MilvusPlugin) Priority() int {
	return 50
}

var defaultMilvusPluginPorts = probe.Ports((&MilvusPlugin{}).PortPriority)

func (p *MilvusPlugin) DefaultPorts() []int { return defaultMilvusPluginPorts }
func (p *MilvusPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
