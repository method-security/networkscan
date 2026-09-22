package rsync

import (
	"context"
	"net"
	"strings"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

type RSYNCPlugin struct{}

const (
	RsyncMagicHeaderLength = 8
	RSYNC                  = "rsync"
)

func (p *RSYNCPlugin) PortPriority(port uint16) bool {
	return port == 873
}

// Run
/*
   rsync is a file synchronization protocol that can run over a number of protocols. Once
   a communication stream is set up between the sender and receiver processes, the protocol is the same, regardless
   of whether that stream is a unix pipe, an SSH connection, or a raw TCP socket. This program detects the
   presence of an rsync daemon, which detects incoming connections and forks to use a raw TCP socket. The
   rsync daemon uses no transport encryption.

   The rsync protocol is not standardized, but all implementations use a magic header "@RSYNCD:" during synchronization.

   This program was tested with docker run -p 873:873 vimagick/rsyncd
   The default port for rsyncd is 873
*/
func (p *RSYNCPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	requestBytes := []byte{

		0x40, 0x52, 0x53, 0x59, 0x4e, 0x43, 0x44, 0x3a,

		0x20,

		0x32, 0x39,

		0x0a,
	}

	response, err := utils.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < RsyncMagicHeaderLength+2 {
		return nil, nil
	}

	if string(response[:RsyncMagicHeaderLength]) == "@RSYNCD:" {
		version := strings.Split(string(response[RsyncMagicHeaderLength+1:]), "\n")[0]
		return probe.Result(target, probe.ServiceRsync{}, false, version, probe.TCP), nil
	}

	return nil, nil
}
func (p *RSYNCPlugin) Name() string {
	return RSYNC
}
func (p *RSYNCPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *RSYNCPlugin) Priority() int {
	return 578
}

var defaultRSYNCPluginPorts = probe.Ports((&RSYNCPlugin{}).PortPriority)

func (p *RSYNCPlugin) DefaultPorts() []int { return defaultRSYNCPluginPorts }
func (p *RSYNCPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
