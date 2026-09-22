// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package linuxrpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

type RPCPlugin struct{}

const RPC = "RPC"

func (p *RPCPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	rpcService := ServiceRPC{}

	check, err := DetectRPCInfoService(conn, &rpcService, timeout)
	if check && err != nil {
		return nil, nil
	}
	if err == nil {
		return helpers.MetadataResult(target, rpcService, false, "", common.TransportTypeTcp), nil
	}
	return nil, err
}
func DetectRPCInfoService(conn net.Conn, lookupResponse *ServiceRPC, timeout time.Duration) (bool, error) {
	callPacket := []byte{
		0x80, 0x00, 0x00, 0x28, 0x72, 0xfe, 0x1d, 0x13,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x01, 0x86, 0xa0, 0x00, 0x01, 0x97, 0x7c,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	callResponseSignature := []byte{
		0x72, 0xfe, 0x1d, 0x13, 0x00, 0x00, 0x00, 0x01,
	}

	dumpPacket := []byte{
		0x80, 0x00, 0x00, 0x28, 0x3d, 0xd3, 0x77, 0x29,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	response, err := utils.SendRecv(conn, callPacket, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, errors.New("service unavailable")
	}

	if !bytes.Contains(response, callResponseSignature) {
		return true, fmt.Errorf("%s: invalid response", RPC)
	}

	response, err = utils.SendRecv(conn, dumpPacket, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, errors.New("service unavailable")
	}

	return true, parseRPCInfo(response, lookupResponse)
}
func parseRPCInfo(response []byte, lookupResponse *ServiceRPC) error {
	if len(response) < 0x20 {
		return fmt.Errorf("invalid rpc length")
	}
	response = response[0x20:]
	valueFollows := 1

	for valueFollows == 1 {
		tmp := RPCB{}
		if len(response) < 0x20 {
			return nil
		}

		tmp.Program = int(binary.BigEndian.Uint32(response[0:4]))
		response = response[4:]
		tmp.Version = int(binary.BigEndian.Uint32(response[0:4]))
		response = response[4:]
		networkIDLen := int(binary.BigEndian.Uint32(response[0:4]))
		for networkIDLen%4 != 0 {
			networkIDLen++
		}
		response = response[4:]
		tmp.Protocol = string(response[0:networkIDLen])
		response = response[networkIDLen:]
		addressLen := int(binary.BigEndian.Uint32(response[0:4]))
		for addressLen%4 != 0 {
			addressLen++
		}
		response = response[4:]
		tmp.Address = string(response[0:addressLen])
		response = response[addressLen:]
		ownerLen := int(binary.BigEndian.Uint32(response[0:4]))
		for ownerLen%4 != 0 {
			ownerLen++
		}
		response = response[4:]
		tmp.Owner = string(response[0:ownerLen])
		response = response[ownerLen:]

		valueFollows = int(binary.BigEndian.Uint32(response[0:4]))
		response = response[4:]

		lookupResponse.Entries = append(lookupResponse.Entries, tmp)
	}

	return nil
}
func (p *RPCPlugin) PortPriority(i uint16) bool {
	return i == 111
}
func (p *RPCPlugin) Name() string {
	return RPC
}
func (p *RPCPlugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *RPCPlugin) Priority() int {
	return 300
}

var defaultRPCPluginPorts = helpers.Ports((&RPCPlugin{}).PortPriority)

func (p *RPCPlugin) DefaultPorts() []int { return defaultRPCPluginPorts }
func (p *RPCPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
