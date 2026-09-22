// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package rdp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

type RDPPlugin struct{}
type TLSPlugin struct{}

const RDP = "rdp"

// checkSignature checks if a given response matches the expected signature for
// the response
func checkSignature(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
func (p *RDPPlugin) PortPriority(port uint16) bool {
	return port == 3389
}
func (p *TLSPlugin) PortPriority(port uint16) bool {
	return port == 3389
}

// getOperatingSystemSignatures returns operating system specific signatures
// for the RDP service.
func getOperatingSystemSignatures() map[string][]byte {
	Windows2000 := []byte{
		0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
	}

	WindowsServer2003 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
		0x03, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2008 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	Windows7OrServer2008R2 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x09, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2008R2DC := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x01, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	Windows10 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x1f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2012Or8 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x0f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2016or2019 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x1f, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00,
	}

	signatures := map[string][]byte{
		"Windows 2000":                Windows2000,
		"Windows Server 2003":         WindowsServer2003,
		"Windows Server 2008":         WindowsServer2008,
		"Windows 7 or Server 2008 R2": Windows7OrServer2008R2,
		"Windows Server 2008 R2 DC":   WindowsServer2008R2DC,
		"Windows 10":                  Windows10,
		"Windows 8 or Server 2012":    WindowsServer2012Or8,
		"Windows Server 2016 or 2019": WindowsServer2016or2019,
	}

	return signatures
}

// checkIsRDPGeneric leverages a generic RDP signature to identify if the
// target port is running the RDP service.
func checkRDP(response []byte) bool {
	GenericRDPSignature := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
	}

	signature := GenericRDPSignature
	signatureLength := len(GenericRDPSignature)

	if len(response) < signatureLength {
		return false
	}

	responseSlice := response[:signatureLength]
	tof := checkSignature(responseSlice, signature)
	return tof
}

// guessOS tries to leverage operating system specific signatures to identify
// if the target port is running a specific operating system.
func guessOS(response []byte) (bool, string) {
	signatures := getOperatingSystemSignatures()
	for fingerprint, signature := range signatures {
		signatureLength := len(signature)

		if len(response) < signatureLength {
			continue
		}

		responseSlice := response[:signatureLength]
		tof := checkSignature(responseSlice, signature)
		if tof {
			return true, fingerprint
		}
	}

	return false, ""
}
func DetectRDP(conn net.Conn, timeout time.Duration) (string, bool, error) {
	InitialConnectionPacket := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x0b,
		0x00, 0x00, 0x00,
	}

	response, err := utils.SendRecv(conn, InitialConnectionPacket, timeout)
	if err != nil {
		return "", false, err
	}
	if len(response) == 0 {
		return "", true, &utils.ServerNotEnable{}
	}

	isRDP := checkRDP(response)
	fingerprint := ""
	if isRDP {
		success, osFingerprint := guessOS(response)
		if success {
			fingerprint = osFingerprint
		}

		return fingerprint, true, nil
	}
	return "", true, &utils.InvalidResponseError{Service: RDP}
}
func DetectRDPAuth(conn net.Conn, timeout time.Duration) (*probe.ServiceRDP, bool, error) {

	NegotiatePacket := []byte{
		0x30, 0x37, 0xA0, 0x03, 0x02, 0x01, 0x60, 0xA1, 0x30, 0x30, 0x2E, 0x30, 0x2C, 0xA0, 0x2A, 0x04, 0x28,

		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,

		0x01, 0x00, 0x00, 0x00,

		0xF7, 0xBA, 0xDB, 0xE2,

		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,

		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,

		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	response, err := utils.SendRecv(conn, NegotiatePacket, timeout)
	if err != nil {
		return nil, false, err
	}
	return parseRDPAuth(response)
}

func parseRDPAuth(response []byte) (*probe.ServiceRDP, bool, error) {
	info := probe.ServiceRDP{}

	type NTLMChallenge struct {
		Signature              [8]byte
		MessageType            uint32
		TargetNameLen          uint16
		TargetNameMaxLen       uint16
		TargetNameBufferOffset uint32
		NegotiateFlags         uint32
		ServerChallenge        uint64
		Reserved               uint64
		TargetInfoLen          uint16
		TargetInfoMaxLen       uint16
		TargetInfoBufferOffset uint32
		Version                [8]byte
	}
	var challengeLen = 56

	challengeStartOffset := bytes.Index(response, []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0})
	if challengeStartOffset == -1 {
		return nil, false, nil
	}
	if len(response) < challengeStartOffset+challengeLen {
		return nil, false, nil
	}
	var responseData NTLMChallenge
	response = response[challengeStartOffset:]
	responseBuf := bytes.NewBuffer(response)
	err := binary.Read(responseBuf, binary.LittleEndian, &responseData)
	if err != nil {
		return nil, false, err
	}

	if responseData.MessageType != 0x00000002 ||
		responseData.Reserved != 0 ||
		!reflect.DeepEqual(responseData.Version[4:], []byte{0, 0, 0, 0xF}) {
		return nil, false, nil
	}

	// Parse: Version
	type version struct {
		MajorVersion byte
		MinorVersion byte
		BuildNumber  uint16
	}
	var versionData version
	versionBuf := bytes.NewBuffer(responseData.Version[:4])
	err = binary.Read(versionBuf, binary.LittleEndian, &versionData)
	if err != nil {
		return nil, true, err
	}
	info.OSVersion = fmt.Sprintf("%d.%d.%d", versionData.MajorVersion,
		versionData.MinorVersion,
		versionData.BuildNumber)

	targetNameLen := int(responseData.TargetNameLen)
	if targetNameLen > 0 {
		if uint64(responseData.TargetNameBufferOffset)+uint64(targetNameLen) > uint64(len(response)) {
			return nil, false, fmt.Errorf("invalid TargetName buffer")
		}
		startIdx := int(responseData.TargetNameBufferOffset)
		endIdx := startIdx + targetNameLen
		targetName := strings.ReplaceAll(string(response[startIdx:endIdx]), "\x00", "")
		info.TargetName = targetName
	}

	targetInfoLen := int(responseData.TargetInfoLen)
	if targetInfoLen > 0 {
		if uint64(responseData.TargetInfoBufferOffset)+uint64(targetInfoLen) > uint64(len(response)) {
			return nil, false, fmt.Errorf("invalid TargetInfo buffer")
		}
		startIdx := int(responseData.TargetInfoBufferOffset)
		pairs := response[startIdx : startIdx+targetInfoLen]
		for {
			if len(pairs) < 4 {
				return nil, false, fmt.Errorf("truncated AV_PAIR header or missing terminator")
			}
			id := binary.LittleEndian.Uint16(pairs)
			length := int(binary.LittleEndian.Uint16(pairs[2:]))
			pairs = pairs[4:]
			if length > len(pairs) {
				return nil, false, fmt.Errorf("truncated AV_PAIR value")
			}
			if id == 0 {
				if length != 0 {
					return nil, false, fmt.Errorf("invalid AV_PAIR terminator")
				}
				break
			}
			value := strings.ReplaceAll(string(pairs[:length]), "\x00", "")
			switch id {
			case 1:
				info.NetBIOSComputerName = value
			case 2:
				info.NetBIOSDomainName = value
			case 3:
				info.DNSComputerName = value
			case 4:
				info.DNSDomainName = value
			case 5:
				info.ForestName = value
			}
			pairs = pairs[length:]
		}
	}

	return &info, true, nil
}
func (p *RDPPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	fingerprint, check, err := DetectRDP(conn, timeout)
	if check && err != nil {
		return nil, nil
	} else if check && err == nil {
		payload := probe.ServiceRDP{
			OSFingerprint: fingerprint,
		}
		return probe.Result(target, payload, false, "", probe.TCP), nil
	}
	return nil, err
}
func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	info, check, err := DetectRDPAuth(conn, timeout)
	if check && err != nil {
		return nil, nil
	} else if check && info != nil && err == nil {
		return probe.Result(target, *info, true, "", probe.TCP), nil
	}
	return nil, err
}
func (p *RDPPlugin) Name() string {
	return RDP
}
func (p *RDPPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *TLSPlugin) Name() string {
	return RDP
}
func (p *TLSPlugin) Type() probe.Protocol {
	return probe.TCPTLS
}
func (p *RDPPlugin) Priority() int {
	return 89
}
func (p *TLSPlugin) Priority() int {
	return 89
}

var defaultRDPPluginPorts = probe.Ports((&RDPPlugin{}).PortPriority)

func (p *RDPPlugin) DefaultPorts() []int { return defaultRDPPluginPorts }
func (p *RDPPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}

var defaultTLSPluginPorts = probe.Ports((&TLSPlugin{}).PortPriority)

func (p *TLSPlugin) DefaultPorts() []int { return defaultTLSPluginPorts }
func (p *TLSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
