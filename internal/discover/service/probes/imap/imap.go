// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package imap

import (
	"context"
	"net"
	"strings"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

type IMAPPlugin struct{}
type TLSPlugin struct{}

const IMAP = "imap"
const IMAPS = "imaps"

/*
	checkGreeting - verifies server greeting.

/* When a client initiates a TCP handshake with an IMAP server, the server will
/* send one of three greetings immediately following the last ACK of the
/* handshake:
/*		S: * OK <status information>
/*		S: * PREAUTH <status information>
/*		S: * BYE <status information>
*/
func checkGreeting(response []byte) bool {
	srvGreet := string(response)
	srvGreetUpper := strings.ToUpper(srvGreet)

	greetings := []string{"* OK", "* PREAUTH", "* BYE"}
	for _, greeting := range greetings {
		if strings.HasPrefix(srvGreetUpper, greeting) {
			return true
		}
	}

	return false
}

/*
	checkCapability - sends CAPABILITY command and verifies response data.

/* CAPABILITY is an unauthenticated IMAP command that allows the client to view
/* what other commands are supported by the server. If an IP:port is running
/* IMAP, it will return data like so:
/* 		C: 1234 CAPABILITY\r\n
/* 		S: * CAPABILITY <list of supported features>\r\n
/* 		S: 1234 OK <status information>\r\n
*/
func checkCapability(conn net.Conn, timeout time.Duration) (bool, error) {

	tag := "7FYWU8I4"
	msg := []byte(tag + " CAPABILITY\r\n")

	response, err := utils.SendRecv(conn, msg, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, &utils.ServerNotEnable{}
	}

	srvResponses := strings.Split(string(response), "\r\n")

	if len(srvResponses) < 2 {
		return true, &utils.InvalidResponseError{Service: IMAP}
	}

	capData := strings.ToUpper(srvResponses[0])
	status := strings.ToUpper(srvResponses[1])

	if status == "" {
		response, err := utils.Recv(conn, timeout)
		if err != nil {
			return false, err
		}
		if len(response) == 0 {
			return true, &utils.ServerNotEnable{}
		}
		status = string(response)
	}

	if !strings.HasPrefix(capData, "* CAPABILITY") || !strings.HasPrefix(status, tag) {
		return true, &utils.InvalidResponseErrorInfo{Service: IMAP, Info: "missing capability info"}
	}

	return false, nil
}
func DetectIMAP(conn net.Conn, timeout time.Duration) (string, bool, error) {

	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return "", false, err
	}
	if len(response) == 0 {
		return "", true, &utils.ServerNotEnable{}
	}

	if !checkGreeting(response) {
		return "", true, &utils.InvalidResponseErrorInfo{
			Service: IMAP,
			Info:    "did not receive expected imap greeting banner",
		}
	}
	check, err := checkCapability(conn, timeout)
	return strings.TrimSpace(string(response)), check, err
}
func (p *IMAPPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	result, check, err := DetectIMAP(conn, timeout)
	if err != nil && check {
		return nil, nil
	} else if err != nil && !check {
		return nil, err
	}

	payload := probe.ServiceIMAP{
		Banner: result,
	}
	return probe.Result(target, payload, false, "", probe.TCP), nil
}
func (p *IMAPPlugin) PortPriority(i uint16) bool {
	return i == 143
}
func (p *IMAPPlugin) Name() string {
	return IMAP
}
func (p *IMAPPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	result, check, err := DetectIMAP(conn, timeout)
	if err != nil && check {
		return nil, nil
	} else if err != nil && !check {
		return nil, err
	}

	payload := probe.ServiceIMAPS{
		Banner: result,
	}
	return probe.Result(target, payload, true, "", probe.TCP), nil
}
func (p *TLSPlugin) PortPriority(i uint16) bool {
	return i == 993
}
func (p *TLSPlugin) Name() string {
	return IMAPS
}
func (p *IMAPPlugin) Priority() int {
	return 191
}
func (p *TLSPlugin) Priority() int {
	return 190
}
func (p *TLSPlugin) Type() probe.Protocol {
	return probe.TCPTLS
}

var defaultIMAPPluginPorts = probe.Ports((&IMAPPlugin{}).PortPriority)

func (p *IMAPPlugin) DefaultPorts() []int { return defaultIMAPPluginPorts }
func (p *IMAPPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}

var defaultTLSPluginPorts = probe.Ports((&TLSPlugin{}).PortPriority)

func (p *TLSPlugin) DefaultPorts() []int { return defaultTLSPluginPorts }
func (p *TLSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
