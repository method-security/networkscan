// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package rsync

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
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
func (p *RSYNCPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
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
		return helpers.MetadataResult(target, ServiceRsync{}, false, version, common.TransportTypeTcp), nil
	}

	return nil, nil
}
func (p *RSYNCPlugin) Name() string {
	return RSYNC
}
func (p *RSYNCPlugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *RSYNCPlugin) Priority() int {
	return 578
}

var defaultRSYNCPluginPorts = helpers.Ports((&RSYNCPlugin{}).PortPriority)

func (p *RSYNCPlugin) DefaultPorts() []int { return defaultRSYNCPluginPorts }
func (p *RSYNCPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
