package mqtt5

import (
	"context"
	"net"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

type MQTT5Plugin struct{}
type TLSPlugin struct{}

const MQTT = "mqtt5"
const MQTTTLS = "mqtt5tls"

func testConnectRequest(conn net.Conn, requestBytes []byte, timeout time.Duration) (bool, error) {
	response, err := utils.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, &utils.ServerNotEnable{}
	}

	if len(response) >= 5 && response[0] == 0x20 && int(response[1]) == len(response)-2 && response[2] <= 1 {

		return true, nil
	}
	return true, &utils.InvalidResponseError{Service: MQTT}
}
func (p *MQTT5Plugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	return Run(conn, timeout, false, target)
}
func (p *MQTT5Plugin) PortPriority(i uint16) bool {
	return i == 1883
}
func (p *MQTT5Plugin) Priority() int {
	return 505
}
func (p *TLSPlugin) Priority() int {
	return 506
}
func (p *MQTT5Plugin) Name() string {
	return MQTT
}
func (p *MQTT5Plugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	return Run(conn, timeout, true, target)
}
func (p *TLSPlugin) PortPriority(i uint16) bool {
	return i == 8883
}
func (p *TLSPlugin) Name() string {
	return MQTTTLS
}
func (p *TLSPlugin) Type() probe.Protocol {
	return probe.TCPTLS
}
func Run(conn net.Conn, timeout time.Duration, tls bool, target probe.Target) (*probe.Service, error) {

	mqttConnect5 := []byte{

		0x10,

		0x12,

		0x00, 0x04,

		0x4d, 0x51, 0x54, 0x54,

		0x05,

		0x02,

		0x00, 0x3c,

		0x00,

		0x00, 0x05,

		0x41, 0x41, 0x41, 0x41, 0x41,
	}

	check, err := testConnectRequest(conn, mqttConnect5, timeout)
	if check && err == nil {
		return probe.Result(target, probe.ServiceMQTT{}, tls, "5.0", probe.TCP), nil
	} else if check && err != nil {
		return nil, nil
	}
	return nil, err
}

var defaultMQTT5PluginPorts = probe.Ports((&MQTT5Plugin{}).PortPriority)

func (p *MQTT5Plugin) DefaultPorts() []int { return defaultMQTT5PluginPorts }
func (p *MQTT5Plugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}

var defaultTLSPluginPorts = probe.Ports((&TLSPlugin{}).PortPriority)

func (p *TLSPlugin) DefaultPorts() []int { return defaultTLSPluginPorts }
func (p *TLSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
