// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package jdwp

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

type JDWPPlugin struct{}

const JDWP = "jdwp"

var (
	commonJDWPPorts = map[int]struct{}{
		3999:  {},
		5000:  {},
		5005:  {},
		8000:  {},
		8453:  {},
		8787:  {},
		8788:  {},
		9001:  {},
		18000: {},
	}
)

type JDWPPacket struct {
	Length     uint32
	ID         uint32
	Flags      byte
	CommandSet byte
	Command    byte
}

func DetectJDWPVersion(conn net.Conn, timeout time.Duration) (*ServiceJDWP, error) {
	info := ServiceJDWP{}

	versionRequest := JDWPPacket{
		Length:     0x0B,
		ID:         0x01,
		Flags:      0x00,
		CommandSet: 0x01,
		Command:    0x01,
	}

	versionBuf := new(bytes.Buffer)
	err := binary.Write(versionBuf, binary.BigEndian, versionRequest)
	if err != nil {
		return nil, err
	}

	response, err := utils.SendRecv(conn, versionBuf.Bytes(), timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 11 {
		return nil, nil
	}

	var versionResponse JDWPPacket
	responseBuf := bytes.NewBuffer(response)
	err = binary.Read(responseBuf, binary.BigEndian, &versionResponse)
	if err != nil {
		return nil, err
	}

	if versionResponse.Length != (uint32(len((response)))) {
		return nil, err
	}

	var descriptionLength uint32
	err = binary.Read(responseBuf, binary.BigEndian, &descriptionLength)
	if err != nil {
		return nil, err
	}
	if uint64(descriptionLength) > uint64(responseBuf.Len()) {
		return nil, nil
	}
	description := make([]byte, descriptionLength)
	err = binary.Read(responseBuf, binary.BigEndian, &description)
	if err != nil {
		return nil, err
	}

	var jdwpMajor int32
	err = binary.Read(responseBuf, binary.BigEndian, &jdwpMajor)
	if err != nil {
		return nil, err
	}
	var jdwpMinor int32
	err = binary.Read(responseBuf, binary.BigEndian, &jdwpMinor)
	if err != nil {
		return nil, err
	}

	var vmVersionLength uint32
	err = binary.Read(responseBuf, binary.BigEndian, &vmVersionLength)
	if err != nil {
		return nil, err
	}
	if uint64(vmVersionLength) > uint64(responseBuf.Len()) {
		return nil, nil
	}
	vmVersion := make([]byte, vmVersionLength)
	err = binary.Read(responseBuf, binary.BigEndian, &vmVersion)
	if err != nil {
		return nil, err
	}

	var vmNameLength uint32
	err = binary.Read(responseBuf, binary.BigEndian, &vmNameLength)
	if err != nil {
		return nil, err
	}
	if uint64(vmNameLength) > uint64(responseBuf.Len()) {
		return nil, nil
	}
	vmName := make([]byte, vmNameLength)
	err = binary.Read(responseBuf, binary.BigEndian, &vmName)
	if err != nil {
		return nil, err
	}

	info.Description = string(description)
	info.JdwpMajor = jdwpMajor
	info.JdwpMinor = jdwpMinor
	info.VMVersion = string(vmVersion)
	info.VMName = string(vmName)

	return &info, nil
}
func (p *JDWPPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	requestBytes := []byte{

		0x4a, 0x44, 0x57, 0x50, 0x2d, 0x48, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61, 0x6b, 0x65,
	}

	response, err := utils.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	if !bytes.Equal(requestBytes, response) {
		return nil, nil
	}

	info, err := DetectJDWPVersion(conn, timeout)
	if err != nil {
		return nil, err
	}

	if info == nil {
		return helpers.MetadataResult(target, ServiceJDWP{}, false, "", common.TransportTypeTcp), nil
	}

	return helpers.MetadataResult(target, info, false, info.VMVersion, common.TransportTypeTcp), nil
}
func (p *JDWPPlugin) PortPriority(port uint16) bool {
	_, ok := commonJDWPPorts[int(port)]
	return ok
}
func (p *JDWPPlugin) Name() string {
	return JDWP
}
func (p *JDWPPlugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *JDWPPlugin) Priority() int {
	return 500
}

var defaultJDWPPluginPorts = helpers.Ports((&JDWPPlugin{}).PortPriority)

func (p *JDWPPlugin) DefaultPorts() []int { return defaultJDWPPluginPorts }
func (p *JDWPPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
