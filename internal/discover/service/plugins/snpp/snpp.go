// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package snpp

import (
	"bytes"
	"context"
	"net"
	"regexp"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

type SNPPPlugin struct{}

const SNPP = "snpp"

// snppBannerRegex matches SNPP greeting banners with "SNPP" in the text
// The 220 code indicates the server is ready to accept commands
var snppBannerRegex = regexp.MustCompile(`^220[- ].*(?i:snpp)`)

// snpp220Regex matches any 220 response (server ready)
var snpp220Regex = regexp.MustCompile(`^220[- ]`)

// snppHelpRegex matches SNPP help response lines (214 code)
var snppHelpRegex = regexp.MustCompile(`^214[- ].*(?i:snpp)`)

func (p *SNPPPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {

	response := readUntilNewline(conn, timeout)

	if len(response) == 0 {
		return nil, nil
	}

	if isValidSNPPBanner(response) {
		payload := ServiceSNPP{
			Banner: string(bytes.TrimSpace(response)),
		}
		return helpers.MetadataResult(target, payload, false, "", common.TransportTypeTcp), nil
	}

	if !snpp220Regex.Match(response) {
		return nil, nil
	}

	helpResponse, err := sendHelpCommand(conn, timeout)
	if err != nil {
		return nil, nil
	}

	if snppHelpRegex.Match(helpResponse) {
		payload := ServiceSNPP{
			Banner: string(bytes.TrimSpace(response)),
		}
		return helpers.MetadataResult(target, payload, false, "", common.TransportTypeTcp), nil
	}

	return nil, nil
}
func readUntilNewline(conn net.Conn, timeout time.Duration) []byte {
	var response []byte
	const maxIterations = 10

	for i := 0; i < maxIterations; i++ {
		data, err := utils.Recv(conn, timeout)
		if err != nil {
			return response
		}
		if len(data) == 0 {
			break
		}
		response = append(response, data...)

		if bytes.Contains(response, []byte("\n")) {
			break
		}
	}
	return response
}
func sendHelpCommand(conn net.Conn, timeout time.Duration) ([]byte, error) {

	_, err := conn.Write([]byte("HELP\r\n"))
	if err != nil {
		return nil, err
	}

	// Read response - may come in multiple packets
	var response []byte
	const maxIterations = 10

	for i := 0; i < maxIterations; i++ {
		data, err := utils.Recv(conn, timeout)
		if err != nil {
			break
		}
		if len(data) == 0 {
			break
		}
		response = append(response, data...)

		if bytes.Contains(response, []byte("259")) || snppHelpRegex.Match(response) {
			break
		}
	}

	return response, nil
}

// isValidSNPPBanner checks if the response is a valid SNPP greeting
func isValidSNPPBanner(response []byte) bool {

	if len(response) < 3 {
		return false
	}

	return snppBannerRegex.Match(response)
}
func (p *SNPPPlugin) PortPriority(port uint16) bool {
	return port == 444
}
func (p *SNPPPlugin) Name() string {
	return SNPP
}
func (p *SNPPPlugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *SNPPPlugin) Priority() int {
	return 10
}

var defaultSNPPPluginPorts = helpers.Ports((&SNPPPlugin{}).PortPriority)

func (p *SNPPPlugin) DefaultPorts() []int { return defaultSNPPPluginPorts }
func (p *SNPPPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
