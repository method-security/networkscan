// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted for networkscan; see ../NOTICE.md.

package pop3

import (
	"context"
	"net"
	"strings"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
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
func (p *POP3Plugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	result, check, err := DetectPOP3(conn, timeout, false)

	if check && err != nil {
		return nil, nil
	} else if !check && err != nil {
		return nil, err
	}

	payload := probe.ServicePOP3{
		Banner: result,
	}
	return probe.Result(target, payload, false, "", probe.TCP), nil
}
func (p *TLSPlugin) PortPriority(port uint16) bool {
	return port == 995
}
func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	result, check, err := DetectPOP3(conn, timeout, true)

	if check && err != nil {
		return nil, nil
	} else if !check && err != nil {
		return nil, err
	}

	payload := probe.ServicePOP3S{
		Banner: result,
	}
	return probe.Result(target, payload, true, "", probe.TCP), nil
}
func (p *POP3Plugin) Name() string {
	return POP3
}
func (p *POP3Plugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *TLSPlugin) Name() string {
	return POP3S
}
func (p *TLSPlugin) Type() probe.Protocol {
	return probe.TCPTLS
}
func (p *POP3Plugin) Priority() int {
	return 120
}
func (p *TLSPlugin) Priority() int {
	return 122
}

var defaultPOP3PluginPorts = probe.Ports((&POP3Plugin{}).PortPriority)

func (p *POP3Plugin) DefaultPorts() []int { return defaultPOP3PluginPorts }
func (p *POP3Plugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}

var defaultTLSPluginPorts = probe.Ports((&TLSPlugin{}).PortPriority)

func (p *TLSPlugin) DefaultPorts() []int { return defaultTLSPluginPorts }
func (p *TLSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
