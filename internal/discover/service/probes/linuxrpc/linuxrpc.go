// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted for networkscan; see ../NOTICE.md.

package linuxrpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

type RPCPlugin struct{}

const RPC = "RPC"

func (p *RPCPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	rpcService := probe.ServiceRPC{}

	check, err := DetectRPCInfoService(conn, &rpcService, timeout)
	if check && err != nil {
		return nil, nil
	}
	if err == nil {
		return probe.Result(target, rpcService, false, "", probe.TCP), nil
	}
	return nil, err
}
func DetectRPCInfoService(conn net.Conn, lookupResponse *probe.ServiceRPC, timeout time.Duration) (bool, error) {
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
		return true, &utils.ServerNotEnable{}
	}

	if !bytes.Contains(response, callResponseSignature) {
		return true, &utils.InvalidResponseError{Service: RPC}
	}

	response, err = utils.SendRecv(conn, dumpPacket, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, &utils.ServerNotEnable{}
	}

	return true, parseRPCInfo(response, lookupResponse)
}
func parseRPCInfo(response []byte, lookupResponse *probe.ServiceRPC) error {
	if len(response) < 0x20 {
		return fmt.Errorf("invalid rpc length")
	}
	response = response[0x20:]
	valueFollows := 1

	for valueFollows == 1 {
		tmp := probe.RPCB{}
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
func (p *RPCPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *RPCPlugin) Priority() int {
	return 300
}

var defaultRPCPluginPorts = probe.Ports((&RPCPlugin{}).PortPriority)

func (p *RPCPlugin) DefaultPorts() []int { return defaultRPCPluginPorts }
func (p *RPCPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
