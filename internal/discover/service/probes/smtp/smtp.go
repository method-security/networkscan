// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted for networkscan; see ../NOTICE.md.

package smtp

import (
	"bytes"
	"context"
	"net"
	"strings"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

type SMTPPlugin struct{}
type TLSPlugin struct{}

const SMTP = "smtp"
const SMTPS = "smtps"

type Data struct {
	Banner      string
	AuthMethods []string
}

func (p *SMTPPlugin) PortPriority(port uint16) bool {
	return port == 25 || port == 587 || port == 465 || port == 2525
}
func handleSMTPConn(response []byte) (bool, bool) {
	if len(response) < 3 {
		return false, false
	}

	validResponses := []string{"220", "421", "500", "501", "554"}
	isSMTP := false
	isSMTPErr := false
	for i := 0; i < len(validResponses); i++ {
		if bytes.Equal(response[0:3], []byte(validResponses[i])) {

			isSMTP = true
			if bytes.Equal(response[0:1], []byte("4")) || bytes.Equal(response[0:1], []byte("5")) {

				isSMTPErr = true
			}
			break
		}
	}
	return isSMTP, isSMTPErr
}
func handleSMTPHelo(response []byte) (bool, bool) {
	if len(response) < 3 {
		return false, false
	}

	validResponses := []string{"250", "421", "500", "501", "502", "504", "550"}
	isSMTP := false
	isSMTPErr := false
	for i := 0; i < len(validResponses); i++ {
		if bytes.Equal(response[0:3], []byte(validResponses[i])) {

			isSMTP = true
			if bytes.Equal(response[0:1], []byte("4")) || bytes.Equal(response[0:1], []byte("5")) {

				isSMTPErr = true
			}
			break
		}
	}
	return isSMTP, isSMTPErr
}
func (p *TLSPlugin) PortPriority(port uint16) bool {
	return port == 465
}
func DetectSMTP(conn net.Conn, tls bool, timeout time.Duration) (Data, bool, error) {
	protocol := SMTP
	if tls {
		protocol = SMTPS
	}

	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return Data{}, false, err
	}
	if len(response) == 0 {
		return Data{}, true, &utils.ServerNotEnable{}
	}

	isSMTP, smtpError := handleSMTPConn(response)
	if !isSMTP && !smtpError {
		return Data{}, true, &utils.InvalidResponseError{Service: protocol}
	}

	banner := make([]byte, len(response))
	copy(banner, response)

	smtpEhloCommand := []byte("EHLO example.com\r\n")
	response, err = utils.SendRecv(conn, smtpEhloCommand, timeout)
	if err != nil {
		return Data{}, false, err
	}
	if len(response) == 0 {
		return Data{}, true, &utils.ServerNotEnable{}
	}

	isSMTP, smtpError = handleSMTPHelo(response)
	if !isSMTP {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: protocol,
			Info:    "invalid SMTP Helo response",
		}
	}

	if smtpError {
		data := Data{
			Banner: string(banner),
		}

		return data, true, nil
	}

	if isSMTP {
		data := Data{
			Banner:      string(banner),
			AuthMethods: strings.Split(strings.ReplaceAll(string(response), "-", " "), " "),
		}

		return data, true, nil
	}

	return Data{}, true, &utils.InvalidResponseError{Service: protocol}
}
func (p *SMTPPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	data, check, err := DetectSMTP(conn, false, timeout)
	if err == nil && check {
		payload := probe.ServiceSMTP{
			Banner:      data.Banner,
			AuthMethods: data.AuthMethods,
		}
		return probe.Result(target, payload, false, "", probe.TCP), nil
	} else if err != nil && check {
		return nil, nil
	}
	return nil, err
}
func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	data, check, err := DetectSMTP(conn, false, timeout)
	if err == nil && check {
		payload := probe.ServiceSMTPS{
			Banner:      data.Banner,
			AuthMethods: data.AuthMethods,
		}
		return probe.Result(target, payload, true, "", probe.TCP), nil
	} else if err != nil && check {
		return nil, nil
	}
	return nil, err
}
func (p *SMTPPlugin) Name() string {
	return SMTP
}
func (p *SMTPPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *TLSPlugin) Name() string {
	return SMTPS
}
func (p *TLSPlugin) Type() probe.Protocol {
	return probe.TCPTLS
}
func (p *SMTPPlugin) Priority() int {
	return 60
}
func (p *TLSPlugin) Priority() int {
	return 61
}

var defaultSMTPPluginPorts = probe.Ports((&SMTPPlugin{}).PortPriority)

func (p *SMTPPlugin) DefaultPorts() []int { return defaultSMTPPluginPorts }
func (p *SMTPPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}

var defaultTLSPluginPorts = probe.Ports((&TLSPlugin{}).PortPriority)

func (p *TLSPlugin) DefaultPorts() []int { return defaultTLSPluginPorts }
func (p *TLSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
