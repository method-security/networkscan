// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package echo

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

type EchoPlugin struct{}

const ECHO = "echo"

func isEcho(conn net.Conn, timeout time.Duration) (bool, error) {

	payload := make([]byte, 64)
	if _, err := rand.Read(payload); err != nil {
		return false, err
	}

	response, err := wireio.SendRecv(conn, payload, timeout)
	if err != nil {
		return false, err
	}

	isEchoService := bytes.Equal(payload, response)

	return isEchoService, nil
}
func (p *EchoPlugin) PortPriority(port uint16) bool {
	return port == 7
}
func (p *EchoPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	if isEcho, err := isEcho(conn, timeout); !isEcho || err != nil {
		return nil, nil
	}
	payload := ServiceEcho{}

	return helpers.MetadataResult(target, payload, false, "", common.TransportTypeTcp), nil
}
func (p *EchoPlugin) Name() string {
	return ECHO
}
func (p *EchoPlugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *EchoPlugin) Priority() int {
	return 1
}

var defaultEchoPluginPorts = helpers.Ports((&EchoPlugin{}).PortPriority)

func (p *EchoPlugin) DefaultPorts() []int { return defaultEchoPluginPorts }
func (p *EchoPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
