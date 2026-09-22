// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted for networkscan; see ../NOTICE.md.

package vnc

import (
	"context"
	"net"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
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
		return "", &utils.InvalidResponseErrorInfo{
			Service: VNC,
			Info:    "incorrect message length",
		}
	}

	if data[0] != 0x52 || data[1] != 0x46 || data[2] != 0x42 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: VNC,
			Info:    "invalid RFB preamble",
		}
	}

	if data[7] != 0x2e || data[11] != 0x0a {
		return "", &utils.InvalidResponseErrorInfo{
			Service: VNC,
			Info:    "missing ProtocolVersion characters",
		}
	}

	return string(data[4:11]), nil
}
func (p *VNCPlugin) PortPriority(port uint16) bool {
	return port == 5900
}
func (p *VNCPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
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

	return probe.Result(target, probe.ServiceVNC{}, false, info, probe.TCP), nil
}
func (p *VNCPlugin) Name() string {
	return VNC
}
func (p *VNCPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *VNCPlugin) Priority() int {
	return 265
}

var defaultVNCPluginPorts = probe.Ports((&VNCPlugin{}).PortPriority)

func (p *VNCPlugin) DefaultPorts() []int { return defaultVNCPluginPorts }
func (p *VNCPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
