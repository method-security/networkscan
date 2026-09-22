// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package openvpn

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

const OPENVPN = "OpenVPN"

type Plugin struct{}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {

	var POpcodeShift uint8 = 3
	var PControlHardResetClientV2 uint8 = 7
	var PControlHardResetServerV2 uint8 = 8
	var SessionIDLength = 8

	InitialConnectionPackage := []byte{
		PControlHardResetClientV2 << POpcodeShift,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0,
		0x0, 0x0, 0x0, 0x0,
	}
	_, err := rand.Read(
		InitialConnectionPackage[1 : 1+SessionIDLength],
	)
	if err != nil {
		return nil, fmt.Errorf("generate %s: random source failed", "session ID")
	}

	response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	if (response[0] >> POpcodeShift) == PControlHardResetServerV2 {
		for i := 0; i < len(response)-SessionIDLength; i++ {
			if reflect.DeepEqual(
				response[i:i+SessionIDLength],
				InitialConnectionPackage[1:1+SessionIDLength],
			) {
				return helpers.MetadataResult(target, ServiceOpenVPN{}, false, "", common.TransportTypeUdp), nil
			}
		}
	}
	return nil, nil
}
func (p *Plugin) PortPriority(i uint16) bool {
	return i == 1194
}
func (p *Plugin) Name() string {
	return OPENVPN
}
func (p *Plugin) Type() common.TransportType {
	return common.TransportTypeUdp
}
func (p *Plugin) Priority() int {
	return 708
}

var defaultPluginPorts = helpers.Ports((&Plugin{}).PortPriority)

func (p *Plugin) DefaultPorts() []int { return defaultPluginPorts }
func (p *Plugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
