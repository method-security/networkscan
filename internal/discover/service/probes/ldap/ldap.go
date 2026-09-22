// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package ldap

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

type LDAPPlugin struct{}
type TLSPlugin struct{}

const LDAP = "ldap"
const LDAPS = "ldaps"

func generateRandomString(length int) []byte {
	charset := "abcdefghijklmnopqrstuvwxyz"
	result := make([]byte, length)

	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return result
}
func generateBindRequestAndID() [2][]byte {
	rand.Seed(time.Now().UnixNano())
	sequenceBERHeader := [2]byte{0x30, 0x3a}
	messageID := uint32(rand.Int31())
	messageIDBytes := [4]byte{}
	binary.BigEndian.PutUint32(messageIDBytes[:], messageID)
	messageIDBERHeader := [2]byte{0x02, 0x04}
	finalMessageIDBER := make([]byte, 6)
	copy(finalMessageIDBER[:2], messageIDBERHeader[:])
	copy(finalMessageIDBER[2:], messageIDBytes[:])
	bindRequestHeader := [2]byte{0x60, 0x32}
	versionBER := [3]byte{0x02, 0x01, 0x03}
	stringBERHeader := [2]byte{0x04, 0x17}
	stringContextBERHeader := [2]byte{0x80, 0x14}

	randomAlphaString := generateRandomString(20)
	dePrefix := []byte("cn=")
	distinguishedName := append(dePrefix, randomAlphaString...)
	passwordBER := randomAlphaString
	combine := [][]byte{
		sequenceBERHeader[:],
		finalMessageIDBER,
		bindRequestHeader[:],
		versionBER[:],
		stringBERHeader[:],
		distinguishedName,
		stringContextBERHeader[:],
		passwordBER,
	}
	fullBindRequest := make([]byte, 60)
	index := 0
	for _, s := range combine {
		index += copy(fullBindRequest[index:], s)
	}

	return [2][]byte{fullBindRequest, finalMessageIDBER}
}
func DetectLDAP(conn net.Conn, timeout time.Duration) (bool, error) {
	requestAndID := generateBindRequestAndID()

	response, err := utils.SendRecv(conn, requestAndID[0], timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return false, nil
	}

	expectedSequenceByte := byte(0x30)
	expectedMessageLengthByte := byte(len(response) - 2)

	expectedLDAPHeader := append(
		[]byte{expectedSequenceByte, expectedMessageLengthByte},
		requestAndID[1]...)

	if len(response) < 7 {
		return false, nil
	}
	otherVersionResponse := append([]byte{response[0]}, response[5]+4)
	otherVersionResponse = append(otherVersionResponse, response[6:]...)

	if bytes.HasPrefix(response, expectedLDAPHeader) || bytes.HasPrefix(otherVersionResponse, expectedLDAPHeader) {
		return true, nil
	}
	return false, nil
}
func (p *LDAPPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	isLDAP, err := DetectLDAP(conn, timeout)
	if err != nil {
		return nil, err
	}

	if isLDAP {
		return probe.Result(target, probe.ServiceLDAP{}, false, "", probe.TCP), nil
	}
	return nil, nil
}
func (p *LDAPPlugin) PortPriority(i uint16) bool {
	return i == 389
}
func (p *LDAPPlugin) Name() string {
	return LDAP
}
func (p *LDAPPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	isLDAPS, err := DetectLDAP(conn, timeout)
	if err != nil {
		return nil, err
	}

	if isLDAPS {
		return probe.Result(target, probe.ServiceLDAPS{}, true, "", probe.TCP), nil
	}
	return nil, nil
}
func (p *TLSPlugin) PortPriority(i uint16) bool {
	return i == 636
}
func (p *LDAPPlugin) Priority() int {
	return 175
}
func (p *TLSPlugin) Priority() int {
	return 175
}
func (p *TLSPlugin) Name() string {
	return LDAPS
}
func (p *TLSPlugin) Type() probe.Protocol {
	return probe.TCPTLS
}

var defaultLDAPPluginPorts = probe.Ports((&LDAPPlugin{}).PortPriority)

func (p *LDAPPlugin) DefaultPorts() []int { return defaultLDAPPluginPorts }
func (p *LDAPPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}

var defaultTLSPluginPorts = probe.Ports((&TLSPlugin{}).PortPriority)

func (p *TLSPlugin) DefaultPorts() []int { return defaultTLSPluginPorts }
func (p *TLSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
