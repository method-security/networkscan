// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted for networkscan; see ../NOTICE.md.

package rtsp

import (
	"context"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
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
func (p *RTSPPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
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
		payload := probe.ServiceRtsp{
			ServerInfo: serverinfo,
		}
		return probe.Result(target, payload, false, "", probe.TCP), nil
	}

	return nil, nil
}
func (p *RTSPPlugin) Name() string {
	return RTSP
}
func (p *RTSPPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *RTSPPlugin) Priority() int {
	return 1001
}

var defaultRTSPPluginPorts = probe.Ports((&RTSPPlugin{}).PortPriority)

func (p *RTSPPlugin) DefaultPorts() []int { return defaultRTSPPluginPorts }
func (p *RTSPPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
