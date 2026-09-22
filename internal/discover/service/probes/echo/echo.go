package echo

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
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
func (p *EchoPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	if isEcho, err := isEcho(conn, timeout); !isEcho || err != nil {
		return nil, nil
	}
	payload := probe.ServiceEcho{}

	return probe.Result(target, payload, false, "", probe.TCP), nil
}
func (p *EchoPlugin) Name() string {
	return ECHO
}
func (p *EchoPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *EchoPlugin) Priority() int {
	return 1
}

var defaultEchoPluginPorts = probe.Ports((&EchoPlugin{}).PortPriority)

func (p *EchoPlugin) DefaultPorts() []int { return defaultEchoPluginPorts }
func (p *EchoPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
