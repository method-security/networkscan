package openvpn

import (
	"context"
	"crypto/rand"
	"net"
	"reflect"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

const OPENVPN = "OpenVPN"

type Plugin struct{}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {

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
		return nil, &utils.RandomizeError{Message: "session ID"}
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
				return probe.Result(target, probe.ServiceOpenVPN{}, false, "", probe.UDP), nil
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
func (p *Plugin) Type() probe.Protocol {
	return probe.UDP
}
func (p *Plugin) Priority() int {
	return 708
}

var defaultPluginPorts = probe.Ports((&Plugin{}).PortPriority)

func (p *Plugin) DefaultPorts() []int { return defaultPluginPorts }
func (p *Plugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
