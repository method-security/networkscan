// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package pop3

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

type POP3Plugin struct{} // POP3

type TLSPlugin struct{} // POP3S

const POP3 = "pop3"
const POP3S = "pop3s"

func (p *POP3Plugin) PortPriority(port uint16) bool {
	return port == 110
}
func DetectPOP3(conn net.Conn, timeout time.Duration, tls bool) (string, bool, error) {

	initialResponse, err := utils.Recv(conn, timeout)
	if err != nil {
		return "", false, err
	}
	if len(initialResponse) == 0 {
		return "", true, &utils.ServerNotEnable{}
	}

	errResponse, err := utils.SendRecv(conn, []byte("Not a command \r\n"), timeout)
	if err != nil {
		return "", false, err
	}
	if len(errResponse) == 0 {
		return "", true, &utils.ServerNotEnable{}
	}

	isPOP3 := false
	if strings.HasPrefix(string(initialResponse), "+OK") &&
		strings.HasPrefix(string(errResponse), "-ERR") {
		isPOP3 = true
	}

	if !isPOP3 {

		if tls {
			return "", true, &utils.InvalidResponseErrorInfo{
				Service: POP3S,
				Info:    "did not get expected banner for POP3S",
			}
		}
		return "", true, &utils.InvalidResponseErrorInfo{
			Service: POP3,
			Info:    "did not get expected banner for POP3",
		}
	}

	return strings.TrimSpace(string(initialResponse[3:])), true, nil
}
func (p *POP3Plugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	result, check, err := DetectPOP3(conn, timeout, false)

	if check && err != nil {
		return nil, nil
	} else if !check && err != nil {
		return nil, err
	}

	payload := ServicePOP3{
		Banner: result,
	}
	return helpers.MetadataResult(target, payload, false, "", common.TransportTypeTcp), nil
}
func (p *TLSPlugin) PortPriority(port uint16) bool {
	return port == 995
}
func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	result, check, err := DetectPOP3(conn, timeout, true)

	if check && err != nil {
		return nil, nil
	} else if !check && err != nil {
		return nil, err
	}

	payload := ServicePOP3S{
		Banner: result,
	}
	return helpers.MetadataResult(target, payload, true, "", common.TransportTypeTcp), nil
}
func (p *POP3Plugin) Name() string {
	return POP3
}
func (p *POP3Plugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *TLSPlugin) Name() string {
	return POP3S
}
func (p *TLSPlugin) Type() common.TransportType {
	return common.TransportTypeTcptls
}
func (p *POP3Plugin) Priority() int {
	return 120
}
func (p *TLSPlugin) Priority() int {
	return 122
}

var defaultPOP3PluginPorts = helpers.Ports((&POP3Plugin{}).PortPriority)

func (p *POP3Plugin) DefaultPorts() []int { return defaultPOP3PluginPorts }
func (p *POP3Plugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}

var defaultTLSPluginPorts = helpers.Ports((&TLSPlugin{}).PortPriority)

func (p *TLSPlugin) DefaultPorts() []int { return defaultTLSPluginPorts }
func (p *TLSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
