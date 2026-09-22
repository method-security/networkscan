package stun

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"net"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

const STUN = "stun"

type Plugin struct{}

var MessageHeaderLength = 20
var FingerprintAttrLength = 8
var BindingResponse = "0101"
var MagicCookie = "2112a442"
var ATTRIBUTES = map[uint32]string{
	0x0001: "MappedAddress",
	0x0006: "Username",
	0x0008: "MessageIntegrity",
	0x0009: "ErrorCode",
	0x000a: "UnknownAttributes",
	0x0014: "Realm",
	0x0015: "Nonce",
	0x0020: "XORMappedAddress",
	0x8022: "Software",
	0x8023: "AlternateServer",
	0x8028: "Fingerprint",
}
var FingerprintXor uint32 = 0x5354554e

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {

	InitialConnectionPackage := []byte{
		0x00, 0x01,
		0x00, 0x0c,
		0x21, 0x12, 0xA4, 0x42,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

		0x80, 0x22,
		0x0, 0x0,

		0x80, 0x28,
		0x0, 0x4,
		0x0, 0x0, 0x0, 0x0,
	}
	_, err := rand.Read(InitialConnectionPackage[8:20])
	if err != nil {
		return nil, &utils.RandomizeError{Message: "transaction ID"}
	}
	TransactionID := hex.EncodeToString(InitialConnectionPackage[8:20])

	fingerprintValue := crc32.ChecksumIEEE(
		InitialConnectionPackage[:len(InitialConnectionPackage)-FingerprintAttrLength],
	) ^ FingerprintXor
	for i := 1; i <= 4; i++ {
		InitialConnectionPackage[len(InitialConnectionPackage)-i] = byte(fingerprintValue & 0xFF)
		fingerprintValue >>= 8
	}

	response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	if len(response) < MessageHeaderLength {
		return nil, nil
	}
	rmsgType, rmagicCookie, rtransID := hex.EncodeToString(response[:2]),
		hex.EncodeToString(response[4:8]),
		hex.EncodeToString(response[8:20])
	if rmsgType != BindingResponse {
		return nil, nil
	}
	if rmagicCookie != MagicCookie {
		return nil, nil
	}
	if rtransID != TransactionID {
		return nil, nil
	}

	infoMap, err := parseResponse(response)
	if err != nil {
		return nil, nil
	}
	payload := probe.ServiceStun{
		Info: fmt.Sprintf("%s", infoMap),
	}

	return probe.Result(target, payload, false, "", probe.UDP), nil
}
func parseResponse(response []byte) (map[string]any, error) {
	if len(response) < MessageHeaderLength {
		return nil, &utils.InvalidResponseErrorInfo{Service: STUN, Info: "truncated message header"}
	}
	messageLength := int(binary.BigEndian.Uint16(response[2:4]))
	if messageLength%4 != 0 || messageLength != len(response)-MessageHeaderLength {
		return nil, &utils.InvalidResponseErrorInfo{Service: STUN, Info: "invalid message length"}
	}
	attrInfo := make(map[string]any)
	idx := MessageHeaderLength
	length := len(response)
	for idx < length {

		if idx+4 > length {
			return nil, &utils.InvalidResponseErrorInfo{
				Service: STUN,
				Info:    "invalid attribute T/L header",
			}
		}
		attrType, attrLen := (int(response[idx])<<8)+int(response[idx+1]),
			(int(response[idx+2])<<8)+int(response[idx+3])
		idx += 4
		if attrLen == 0 {
			continue
		}

		// Attribute lengths exclude padding; the next attribute starts on a 4-byte boundary.
		paddedLen := (attrLen + 3) &^ 3
		if paddedLen > length-idx {
			return nil, &utils.InvalidResponseErrorInfo{
				Service: STUN,
				Info:    "invalid attribute length",
			}
		}
		attrValue := response[idx : idx+attrLen]
		idx += paddedLen
		var attrValueStr string
		attrName, exists := ATTRIBUTES[uint32(attrType)]
		if exists {
			if attrName == "Software" {
				attrValueStr = string(attrValue)
			} else {
				attrValueStr = hex.EncodeToString(attrValue)
			}
		} else {
			attrName = fmt.Sprintf("%04x", attrType)
			attrValueStr = hex.EncodeToString(attrValue)
		}

		_, exists = attrInfo[attrName]
		if !exists {
			attrInfo[attrName] = attrValueStr
		}
	}

	return attrInfo, nil
}
func (p *Plugin) PortPriority(i uint16) bool {
	return i == 3478
}
func (p *Plugin) Name() string {
	return STUN
}
func (p *Plugin) Type() probe.Protocol {
	return probe.UDP
}
func (p *Plugin) Priority() int {
	return 2000
}

var defaultPluginPorts = probe.Ports((&Plugin{}).PortPriority)

func (p *Plugin) DefaultPorts() []int { return defaultPluginPorts }
func (p *Plugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
