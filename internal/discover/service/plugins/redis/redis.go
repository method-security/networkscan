// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package redis

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

type REDISPlugin struct{}
type REDISTLSPlugin struct{}
type Info struct {
	AuthRequired bool
}

const REDIS = "redis"
const REDISTLS = "redis"

// Check if the response is from a Redis server
// returns an error if it's not validated as a Redis server
// and a Info struct with AuthRequired if it is
func checkRedis(data []byte) (Info, error) {

	pong := [7]byte{0x2b, 0x50, 0x4f, 0x4e, 0x47, 0x0d, 0x0a}

	noauth := [7]byte{0x2d, 0x4e, 0x4f, 0x41, 0x55, 0x54, 0x48}

	msgLength := len(data)
	if msgLength < 7 {
		return Info{}, &utils.InvalidResponseErrorInfo{
			Service: REDIS,
			Info:    "too short of a response",
		}
	}

	if msgLength == 7 {
		if bytes.Equal(data, pong[:]) {

			return Info{AuthRequired: false}, nil
		}
		return Info{}, &utils.InvalidResponseErrorInfo{
			Service: REDIS,
			Info:    "invalid PONG response",
		}
	}
	if !bytes.Equal(data[:7], noauth[:]) {
		return Info{}, &utils.InvalidResponseErrorInfo{
			Service: REDIS,
			Info:    "invalid Error response",
		}
	}

	return Info{AuthRequired: true}, nil
}

// extractRedisVersion extracts the Redis version from an INFO SERVER response.
// The INFO command returns a bulk string in RESP format containing key-value pairs.
// Each line is in the format "key:value\r\n" and we look for the "redis_version" field.
//
// Parameters:
//   - response: The INFO SERVER response string containing server metadata
//
// Returns:
//   - string: The Redis version (e.g., "7.4.0"), or empty string if not found
func extractRedisVersion(response string) string {
	if response == "" {
		return ""
	}

	lines := strings.Split(strings.ReplaceAll(response, "\r\n", "\n"), "\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "redis_version:") {

			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	return ""
}

// buildRedisCPE generates a CPE (Common Platform Enumeration) string for Redis servers.
// CPE format: cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" wildcard to match Wappalyzer/RMI/FTP plugin behavior
// and enable asset inventory use cases even without precise version information.
//
// Parameters:
//   - version: Redis version string (e.g., "7.4.0"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" wildcard
func buildRedisCPE(version string) string {

	if version == "" {
		version = "*"
	}

	return fmt.Sprintf("cpe:2.3:a:redis:redis:%s:*:*:*:*:*:*:*", version)
}
func (p *REDISPlugin) PortPriority(port uint16) bool {
	return port == 6379
}
func (p *REDISTLSPlugin) PortPriority(port uint16) bool {
	return port == 6380
}
func (p *REDISTLSPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	return DetectRedis(conn, target, timeout, true)
}
func DetectRedis(conn net.Conn, target helpers.Endpoint, timeout time.Duration, tls bool) (*discover.ServiceDetails, error) {

	ping := []byte{
		0x2a,
		0x31,
		0x0d,
		0x0a,
		0x24,
		0x34,
		0x0d,
		0x0a,
		0x50,
		0x49,
		0x4e,
		0x47,
		0x0d,
		0x0a,
	}

	response, err := utils.SendRecv(conn, ping, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	result, err := checkRedis(response)
	if err != nil {
		return nil, nil
	}

	version := ""
	if !result.AuthRequired {

		infoCmd := []byte{
			0x2a, 0x32, 0x0d, 0x0a,
			0x24, 0x34, 0x0d, 0x0a,
			0x49, 0x4e, 0x46, 0x4f, 0x0d, 0x0a,
			0x24, 0x36, 0x0d, 0x0a,
			0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x0d, 0x0a,
		}

		infoResp, err := utils.SendRecv(conn, infoCmd, timeout)
		if err == nil && len(infoResp) > 0 {

			if len(infoResp) > 2 && infoResp[0] == '$' {

				for i := 1; i < len(infoResp)-1; i++ {
					if infoResp[i] == '\r' && infoResp[i+1] == '\n' {

						dataStart := i + 2
						if dataStart < len(infoResp) {
							infoData := string(infoResp[dataStart:])
							version = extractRedisVersion(infoData)
						}
						break
					}
				}
			}
		}
	}

	cpe := buildRedisCPE(version)

	payload := ServiceRedis{
		AuthRequired: result.AuthRequired,
		CPEs:         []string{cpe},
	}
	if tls {
		return helpers.MetadataResult(target, payload, true, version, common.TransportTypeTcptls), nil
	}
	return helpers.MetadataResult(target, payload, false, version, common.TransportTypeTcp), nil
}
func (p *REDISPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	return DetectRedis(conn, target, timeout, false)
}
func (p *REDISPlugin) Name() string {
	return REDIS
}
func (p *REDISTLSPlugin) Name() string {
	return REDISTLS
}
func (p *REDISPlugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *REDISTLSPlugin) Type() common.TransportType {
	return common.TransportTypeTcptls
}
func (p *REDISPlugin) Priority() int {
	return 413
}
func (p *REDISTLSPlugin) Priority() int {
	return 414
}

var defaultREDISTLSPluginPorts = helpers.Ports((&REDISTLSPlugin{}).PortPriority)

func (p *REDISTLSPlugin) DefaultPorts() []int { return defaultREDISTLSPluginPorts }
func (p *REDISTLSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}

var defaultREDISPluginPorts = helpers.Ports((&REDISPlugin{}).PortPriority)

func (p *REDISPlugin) DefaultPorts() []int { return defaultREDISPluginPorts }
func (p *REDISPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
