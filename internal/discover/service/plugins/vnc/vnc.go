// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package vnc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

type VNCPlugin struct{}

const VNC = "VNC"

// Check if the response is from a VNC server
// https://datatracker.ietf.org/doc/html/rfc6143#section-7.1
// Handshaking begins by the server sending the client a ProtocolVersion message.
//
// The ProtocolVersion message consists of 12 bytes interpreted as a
//
//	string of ASCII characters in the format "RFB xxx.yyy\n" where xxx
//	and yyy are the major and minor version numbers, left-padded with
//	zeros:
//
//	    RFB 003.008\n (hex 52 46 42 20 30 30 33 2e 30 30 38 0a)
func checkVNC(data []byte) (string, error) {
	msgLength := len(data)
	if msgLength != 12 {
		return "", fmt.Errorf("%s: invalid response: %s", VNC,
			"incorrect message length")

	}

	if data[0] != 0x52 || data[1] != 0x46 || data[2] != 0x42 {
		return "", fmt.Errorf("%s: invalid response: %s", VNC,
			"invalid RFB preamble")

	}

	if data[7] != 0x2e || data[11] != 0x0a {
		return "", fmt.Errorf("%s: invalid response: %s", VNC,
			"missing ProtocolVersion characters")

	}

	return string(data[4:11]), nil
}
func (p *VNCPlugin) PortPriority(port uint16) bool {
	return port == 5900
}
func (p *VNCPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	info, err := checkVNC(response)
	if err != nil {
		return nil, nil
	}

	return helpers.MetadataResult(target, ServiceVNC{}, false, info, common.TransportTypeTcp), nil
}
func (p *VNCPlugin) Name() string {
	return VNC
}
func (p *VNCPlugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *VNCPlugin) Priority() int {
	return 265
}

var defaultVNCPluginPorts = helpers.Ports((&VNCPlugin{}).PortPriority)

func (p *VNCPlugin) DefaultPorts() []int { return defaultVNCPluginPorts }
func (p *VNCPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
