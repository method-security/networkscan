// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted for networkscan; see ../NOTICE.md.

package modbus

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

const (
	ModbusHeaderLength      = 7
	ModbusDiscreteInputCode = 0x2
	ModbusErrorAddend       = 0x80
)

type MODBUSPlugin struct{}

const MODBUS = "modbus"

func (p *MODBUSPlugin) PortPriority(port uint16) bool {
	return port == 502
}

// Run
/*
   modbus is a communications standard for connecting industrial devices.
   modbus can be carried over a number of frame formats; this program identifies
   modbus over TCP.

   modbus supports diagnostic functions that could be used for fingerprinting,
   however, not all implementations will support the use of these functions.
   Therefore, this program utilizes a read primitive and validates both the success
   response and the error response conditions.

   modbus supports reading and writing to specified memory addresses using a number
   of different primitives. This program utilizes the "Read Discrete Input" primitive,
   which requests the value of a read-only boolean. This is the least likely primitive to
   be disruptive.

   Additionally, all modbus messages begin with a 7-byte header. The first two bytes are a
   client-controlled transaction ID. This program generates a random transaction ID and validates
   that the server echos the correct response.

   Initial testing done with `docker run -it -p 502:5020 oitc/modbus-server:latest`
   The default TCP port is 502, but this is unofficial.
*/
func (p *MODBUSPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	transactionID := make([]byte, 2)
	_, err := rand.Read(transactionID)
	if err != nil {
		return nil, &utils.RandomizeError{Message: "Transaction ID"}
	}

	requestBytes := []byte{

		0x00, 0x00,

		0x00, 0x06,

		0x01,

		0x02,

		0x00, 0x00,

		0x00, 0x01,
	}

	requestBytes = append(transactionID, requestBytes...)

	response, err := utils.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 9 {
		return nil, nil
	}

	if bytes.Equal(response[:2], transactionID) {

		if len(response) >= 10 && response[ModbusHeaderLength] == ModbusDiscreteInputCode {
			if response[ModbusHeaderLength+1] == 1 && (response[ModbusHeaderLength+2]>>1) == 0x00 {
				return probe.Result(target, probe.ServiceModbus{}, false, "", probe.TCP), nil
			}
		} else if response[ModbusHeaderLength] == ModbusDiscreteInputCode+ModbusErrorAddend {
			return probe.Result(target, probe.ServiceModbus{}, false, "", probe.TCP), nil
		}
	}
	return nil, nil
}
func (p *MODBUSPlugin) Name() string {
	return MODBUS
}
func (p *MODBUSPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *MODBUSPlugin) Priority() int {
	return 400
}

var defaultMODBUSPluginPorts = probe.Ports((&MODBUSPlugin{}).PortPriority)

func (p *MODBUSPlugin) DefaultPorts() []int { return defaultMODBUSPluginPorts }
func (p *MODBUSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
