package mqtt3

import (
	"context"
	"net"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
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
		return true, &utils.ServerNotEnable{}
	}

	if len(response) == 4 && response[0] == 0x20 && response[1] == 2 && response[2] <= 1 && response[3] <= 5 {

		return true, nil
	}
	return true, &utils.InvalidResponseError{Service: MQTT}
}
func (p *MQTT3Plugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	return Run(conn, timeout, false, target)
}
func (p *MQTT3Plugin) PortPriority(i uint16) bool {
	return i == 1883
}
func (p *MQTT3Plugin) Name() string {
	return MQTT
}
func (p *MQTT3Plugin) Type() probe.Protocol {
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
func (p *MQTT3Plugin) Priority() int {
	return 500
}
func (p *TLSPlugin) Priority() int {
	return 501
}
func (p *TLSPlugin) Type() probe.Protocol {
	return probe.TCPTLS
}
func Run(conn net.Conn, timeout time.Duration, tls bool, target probe.Target) (*probe.Service, error) {

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
		return probe.Result(target, probe.ServiceMQTT{}, tls, "3.1.x", probe.TCP), nil
	} else if check && err != nil {
		return nil, nil
	}
	return nil, err
}

var defaultMQTT3PluginPorts = probe.Ports((&MQTT3Plugin{}).PortPriority)

func (p *MQTT3Plugin) DefaultPorts() []int { return defaultMQTT3PluginPorts }
func (p *MQTT3Plugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}

var defaultTLSPluginPorts = probe.Ports((&TLSPlugin{}).PortPriority)

func (p *TLSPlugin) DefaultPorts() []int { return defaultTLSPluginPorts }
func (p *TLSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
