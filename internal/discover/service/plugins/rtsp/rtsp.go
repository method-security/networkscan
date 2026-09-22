// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package rtsp

import (
	"context"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

const (
	RtspMagicHeader        = "RTSP/1.0"
	RtspMagicHeaderLength  = 8
	RtspCseqHeader         = "CSeq: "
	RtspCseqHeaderLength   = 6
	RtspServerHeader       = "Server: "
	RtspServerHeaderLength = 8
	RtspNewlineLength      = 2
	RTSP                   = "rtsp"
)

type RTSPPlugin struct{}

func (p *RTSPPlugin) PortPriority(port uint16) bool {
	return port == 554
}
func (p *RTSPPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	cseq := strconv.Itoa(rand.Intn(10000))

	requestString := strings.Join([]string{
		"OPTIONS rtsp://example.com RTSP/1.0\r\n",
		"Cseq: ", cseq, "\r\n",
		"\r\n",
	}, "")

	requestBytes := []byte(requestString)

	responseBytes, err := utils.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return nil, err
	}
	if len(responseBytes) == 0 {
		return nil, nil
	}
	response := string(responseBytes)

	if len(response) < RtspMagicHeaderLength {
		return nil, nil
	}
	if response[:RtspMagicHeaderLength] == RtspMagicHeader {
		cseqStart := strings.Index(response, RtspCseqHeader)
		if cseqStart == -1 {
			return nil, nil
		}

		cseqValueStart := cseqStart + RtspCseqHeaderLength
		if cseqValueStart+len(cseq)+RtspNewlineLength > len(response) || response[cseqValueStart:cseqValueStart+len(cseq)+RtspNewlineLength] != cseq+"\r\n" {
			return nil, nil
		}

		serverStart := strings.Index(response, RtspServerHeader)
		if serverStart == -1 {
			return nil, nil
		}

		serverValueStart := serverStart + RtspServerHeaderLength
		serverValueEnd := strings.Index(response[serverValueStart:], "\r\n")
		if serverValueEnd < 0 || serverValueStart+serverValueEnd >= len(response) {
			return nil, nil
		}

		serverinfo := response[serverValueStart : serverValueStart+serverValueEnd]
		payload := ServiceRtsp{
			ServerInfo: serverinfo,
		}
		return helpers.MetadataResult(target, payload, false, "", common.TransportTypeTcp), nil
	}

	return nil, nil
}
func (p *RTSPPlugin) Name() string {
	return RTSP
}
func (p *RTSPPlugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *RTSPPlugin) Priority() int {
	return 1001
}

var defaultRTSPPluginPorts = helpers.Ports((&RTSPPlugin{}).PortPriority)

func (p *RTSPPlugin) DefaultPorts() []int { return defaultRTSPPluginPorts }
func (p *RTSPPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
