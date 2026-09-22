// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package mqtt3

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

type MQTT3Plugin struct{}
type TLSPlugin struct{}

const MQTT = "mqtt3"
const MQTTTLS = "mqtt3tls"

func testConnectRequest(conn net.Conn, requestBytes []byte, timeout time.Duration) (bool, error) {
	response, err := utils.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, errors.New("service unavailable")
	}

	if len(response) == 4 && response[0] == 0x20 && response[1] == 2 && response[2] <= 1 && response[3] <= 5 {

		return true, nil
	}
	return true, fmt.Errorf("%s: invalid response", MQTT)
}
func (p *MQTT3Plugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	return Run(conn, timeout, false, target)
}
func (p *MQTT3Plugin) PortPriority(i uint16) bool {
	return i == 1883
}
func (p *MQTT3Plugin) Name() string {
	return MQTT
}
func (p *MQTT3Plugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	return Run(conn, timeout, true, target)
}
func (p *TLSPlugin) PortPriority(i uint16) bool {
	return i == 8883
}
func (p *TLSPlugin) Name() string {
	return MQTTTLS
}
func (p *MQTT3Plugin) Priority() int {
	return 500
}
func (p *TLSPlugin) Priority() int {
	return 501
}
func (p *TLSPlugin) Type() common.TransportType {
	return common.TransportTypeTcptls
}
func Run(conn net.Conn, timeout time.Duration, tls bool, target helpers.Endpoint) (*discover.ServiceDetails, error) {

	mqttConnect3 := []byte{

		0x10,

		0x11,

		0x00, 0x04,

		0x4d, 0x51, 0x54, 0x54,

		0x04,

		0x02,

		0x00, 0x3c,

		0x00, 0x05,

		0x41, 0x41, 0x41, 0x41, 0x41,
	}

	check, err := testConnectRequest(conn, mqttConnect3, timeout)
	if check && err == nil {
		return helpers.MetadataResult(target, ServiceMQTT{}, tls, "3.1.x", common.TransportTypeTcp), nil
	} else if check && err != nil {
		return nil, nil
	}
	return nil, err
}

var defaultMQTT3PluginPorts = helpers.Ports((&MQTT3Plugin{}).PortPriority)

func (p *MQTT3Plugin) DefaultPorts() []int { return defaultMQTT3PluginPorts }
func (p *MQTT3Plugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
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
