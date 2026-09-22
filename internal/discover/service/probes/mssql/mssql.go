// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package mssql

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

// Potential values for PLOptionToken
const (
	VERSION         int  = 0
	ENCRYPTION      int  = 1
	INSTOPT         int  = 2
	THREADID        int  = 3
	MARS            int  = 4
	TRACEID         int  = 5
	FEDAUTHREQUIRED int  = 6
	NONCEOPT        int  = 7
	TERMINATOR      byte = 0xFF
)

type OptionToken struct {
	PLOptionToken  uint32
	PLOffset       uint32
	PLOptionLength uint32
	PLOptionData   []byte // the raw data associated with the option
}
type MSSQLPlugin struct{}
type Data struct {
	Version string
}

const MSSQL = "mssql"

func (p *MSSQLPlugin) PortPriority(port uint16) bool {
	return port == 1433
}

// buildMSSQLCPE generates a CPE (Common Platform Enumeration) string for Microsoft SQL Server.
//
// Uses wildcard version ("*") when version is unknown to match Wappalyzer/RMI/FTP plugin
// behavior and enable asset inventory use cases even without precise version information.
//
// CPE format: cpe:2.3:a:microsoft:sql_server:{version}:*:*:*:*:*:*:*
//
// Parameters:
//   - version: Version string (e.g., "15.0.2000"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" wildcard
func buildMSSQLCPE(version string) string {

	version = strings.TrimSpace(version)

	if version == "" {
		version = "*"
	}

	cpeTemplate := "cpe:2.3:a:microsoft:sql_server:%s:*:*:*:*:*:*:*"

	return fmt.Sprintf(cpeTemplate, version)
}
func DetectMSSQL(conn net.Conn, timeout time.Duration) (Data, bool, error) {

	preLoginPacket := []byte{

		0x12,
		0x01,
		0x00, 0x58,
		0x00, 0x00,
		0x01,
		0x00,

		0x00,
		0x00, 0x1F,
		0x00, 0x06,

		0x01,
		0x00, 0x25,
		0x00, 0x01,

		0x02,
		0x00, 0x26,
		0x00, 0x01,

		0x03,
		0x00, 0x27,
		0x00, 0x04,

		0x04,
		0x00, 0x2B,
		0x00, 0x01,

		0x05,
		0x00, 0x2C,
		0x00, 0x24,

		0xFF,

		0x11, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0xF9, 0xB8, 0xCB,
		0x5C, 0x94, 0x6B, 0x89, 0x1F, 0xD9, 0xAA, 0x3C,
		0x13, 0x4B, 0xD0, 0x7B, 0x88, 0x03, 0x5C, 0x32,
		0x21, 0x24, 0xA2, 0x81, 0x86, 0x37, 0xCF, 0x62,
		0x39, 0x4A, 0x46, 0x2C, 0xC6, 0x00, 0x00, 0x00,
		0x00,
	}

	response, err := utils.SendRecv(conn, preLoginPacket, timeout)
	if err != nil {
		return Data{}, false, err
	}
	if len(response) == 0 {
		return Data{}, true, &utils.ServerNotEnable{}
	}

	if len(response) < 8 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "response is too short to be a valid TDS packet header",
		}
	}

	if response[0] != 0x04 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "type should be set to tabular result for a valid TDS packet",
		}
	}

	if response[1] != 0x01 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "expect a status of one (end of message) for tabular result packet",
		}
	}

	packetLength := int(uint32(response[3]) | uint32(response[2])<<8)
	if len(response) != packetLength {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "packet length does not match length read",
		}
	}

	if response[4] != 0x00 || response[5] != 0x00 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "value for SPID should always be zero",
		}
	}

	if response[6] != 0x01 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "value for packet id should always be one",
		}
	}

	if response[7] != 0x00 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "value for window should always be zero",
		}
	}

	position := 8

	var optionTokens []OptionToken
	for response[position] != TERMINATOR && position < len(response) {
		plOptionToken := uint32(response[position+0])
		plOffset := uint32(response[position+2]) | uint32(response[position+1])<<8
		plOptionLength := uint32(response[position+4]) | uint32(response[position+3])<<8

		plOptionData := []byte{}
		if plOptionLength != 0 {
			if plOffset+plOptionLength < uint32(len(response)) {
				plOptionData = response[plOffset+8 : plOffset+8+plOptionLength]
			} else {
				return Data{}, true, &utils.InvalidResponseErrorInfo{
					Service: MSSQL,
					Info:    "server returned an invalid PLOffset or PLOptionLength"}
			}
		}

		position += 5
		optionTokenStruct := OptionToken{
			PLOptionToken:  plOptionToken,
			PLOffset:       plOffset,
			PLOptionLength: plOptionLength,
			PLOptionData:   plOptionData,
		}

		optionTokens = append(optionTokens, optionTokenStruct)
	}

	if response[position] != 0xFF {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "list of option tokens should be terminated by 0xff",
		}
	}

	if len(optionTokens) < 1 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "there should be at least one option token since VERSION is required",
		}
	}

	if optionTokens[0].PLOptionToken != 0x00 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "TDS requires VERSION to be the first PLOptionToken value",
		}
	}

	if optionTokens[0].PLOptionLength != 0x06 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "version field should be fixed bytes",
		}
	}

	MajorVersion := optionTokens[0].PLOptionData[0]
	MinorVersion := optionTokens[0].PLOptionData[1]
	BuildNumber := uint32(optionTokens[0].PLOptionData[2])*256 + uint32(optionTokens[0].PLOptionData[3])

	version := fmt.Sprintf("%d.%d.%d\n", MajorVersion, MinorVersion, BuildNumber)

	return Data{Version: version}, true, nil
}
func (p *MSSQLPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	data, check, err := DetectMSSQL(conn, timeout)
	if check && err != nil {
		return nil, nil
	} else if !check && err != nil {
		return nil, err
	}

	cpe := buildMSSQLCPE(data.Version)

	payload := probe.ServiceMSSQL{
		CPEs: []string{cpe},
	}

	return probe.Result(target, payload, false, data.Version, probe.TCP), nil
}
func (p *MSSQLPlugin) Name() string {
	return MSSQL
}
func (p *MSSQLPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *MSSQLPlugin) Priority() int {
	return 143
}

var defaultMSSQLPluginPorts = probe.Ports((&MSSQLPlugin{}).PortPriority)

func (p *MSSQLPlugin) DefaultPorts() []int { return defaultMSSQLPluginPorts }
func (p *MSSQLPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
