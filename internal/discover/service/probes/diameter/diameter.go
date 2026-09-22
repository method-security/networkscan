// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package diameter

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

const (
	DIAMETER         = "diameter"
	DIAMETER_PORT    = 3868
	DIAMETER_VERSION = 1
	CER_COMMAND_CODE = 257
	R_BIT            = 0x80 // Request bit
	DIAMETER_SUCCESS = 2001
	AVP_RESULT_CODE  = 268
	AVP_ORIGIN_HOST  = 264
	AVP_ORIGIN_REALM = 296
	AVP_HOST_IP_ADDR = 257
	AVP_VENDOR_ID    = 266
	AVP_PRODUCT_NAME = 269
	AVP_FIRMWARE_REV = 267
	M_BIT            = 0x40 // Mandatory bit
)

type DIAMETERPlugin struct{}

// Run implements the main fingerprinting logic
func (p *DIAMETERPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {

	cea, err := detectDiameter(conn, timeout)
	if err != nil {
		return nil, err
	}

	productName, firmwareRev, err := enrichDiameter(cea)
	if err != nil {

		metadata := ServiceDiameter{}
		return probe.Result(target, metadata, false, "", probe.TCP), nil
	}

	vendor, product := identifyVendor(productName)

	// Decode version from Firmware-Revision
	var version string
	if firmwareRev > 0 {
		version = decodeFirmwareRevision(firmwareRev)
	}

	cpe := buildCPE(vendor, product, version)

	metadata := ServiceDiameter{
		CPEs:    []string{cpe},
		Version: version,
		Vendor:  vendor,
		Product: product,
	}

	return probe.Result(target, metadata, false, version, probe.TCP), nil
}

// PortPriority returns true if the port is 3868 (default Diameter port)
func (p *DIAMETERPlugin) PortPriority(port uint16) bool {
	return port == DIAMETER_PORT
}

// Name returns the protocol name
func (p *DIAMETERPlugin) Name() string {
	return DIAMETER
}

// Type returns the protocol type (TCP)
func (p *DIAMETERPlugin) Type() probe.Protocol {
	return probe.TCP
}

// Priority returns the plugin execution priority
// Diameter uses port 3868 exclusively, run at medium priority (after common services)
func (p *DIAMETERPlugin) Priority() int {
	return 60
}

// detectDiameter sends a CER message and validates the CEA response
func detectDiameter(conn net.Conn, timeout time.Duration) ([]byte, error) {

	cer := buildCER()

	response, err := utils.SendRecv(conn, cer, timeout)
	if err != nil {
		return nil, err
	}

	if err := validateCEA(response); err != nil {
		return nil, err
	}

	return response, nil
}

// buildCER constructs a Capabilities-Exchange-Request message
func buildCER() []byte {

	header := make([]byte, 20)

	header[0] = DIAMETER_VERSION

	header[4] = R_BIT

	binary.BigEndian.PutUint32(header[4:8], CER_COMMAND_CODE)
	header[4] = R_BIT

	binary.BigEndian.PutUint32(header[8:12], 0)

	binary.BigEndian.PutUint32(header[12:16], 12345)

	binary.BigEndian.PutUint32(header[16:20], 67890)

	avps := []byte{}

	avps = append(avps, buildAVP(AVP_ORIGIN_HOST, true, []byte("networkscan.local\x00"))...)

	avps = append(avps, buildAVP(AVP_ORIGIN_REALM, true, []byte("local\x00"))...)

	ipAddr := []byte{0x00, 0x01, 127, 0, 0, 1}
	avps = append(avps, buildAVP(AVP_HOST_IP_ADDR, true, ipAddr)...)

	avps = append(avps, buildAVP(AVP_VENDOR_ID, true, encodeUnsigned32(0))...)

	avps = append(avps, buildAVP(AVP_PRODUCT_NAME, true, []byte("networkscan\x00"))...)

	totalLength := len(header) + len(avps)

	header[1] = byte((totalLength >> 16) & 0xFF)
	header[2] = byte((totalLength >> 8) & 0xFF)
	header[3] = byte(totalLength & 0xFF)

	return append(header, avps...)
}

// buildAVP constructs a Diameter AVP
func buildAVP(code uint32, mandatory bool, data []byte) []byte {

	header := make([]byte, 8)

	binary.BigEndian.PutUint32(header[0:4], code)

	flags := byte(0)
	if mandatory {
		flags |= M_BIT
	}
	header[4] = flags

	avpLength := 8 + len(data)
	header[5] = byte((avpLength >> 16) & 0xFF)
	header[6] = byte((avpLength >> 8) & 0xFF)
	header[7] = byte(avpLength & 0xFF)

	avp := append(header, data...)

	for len(avp)%4 != 0 {
		avp = append(avp, 0x00)
	}

	return avp
}

// encodeUnsigned32 encodes a uint32 in big-endian format
func encodeUnsigned32(value uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return data
}

// validateCEA validates the structure of a Capabilities-Exchange-Answer
func validateCEA(response []byte) error {

	if len(response) < 60 {
		return &utils.InvalidResponseErrorInfo{
			Service: DIAMETER,
			Info:    "response too short for valid CEA",
		}
	}

	if response[0] != DIAMETER_VERSION {
		return &utils.InvalidResponseErrorInfo{
			Service: DIAMETER,
			Info:    fmt.Sprintf("invalid version: %d, expected 1", response[0]),
		}
	}

	msgLength := (uint32(response[1]) << 16) | (uint32(response[2]) << 8) | uint32(response[3])
	if len(response) < int(msgLength) {
		return &utils.InvalidResponseErrorInfo{
			Service: DIAMETER,
			Info:    fmt.Sprintf("incomplete response: got %d bytes, expected %d", len(response), msgLength),
		}
	}

	commandCode := (uint32(response[5]) << 16) | (uint32(response[6]) << 8) | uint32(response[7])
	if commandCode != CER_COMMAND_CODE {
		return &utils.InvalidResponseErrorInfo{
			Service: DIAMETER,
			Info:    fmt.Sprintf("invalid command code: %d, expected 257", commandCode),
		}
	}

	if response[4]&R_BIT != 0 {
		return &utils.InvalidResponseErrorInfo{
			Service: DIAMETER,
			Info:    "R-bit set in CEA (expected answer, not request)",
		}
	}

	return nil
}

// enrichDiameter extracts version and metadata from CEA
func enrichDiameter(cea []byte) (string, uint32, error) {

	offset := 20
	var productName string
	var firmwareRev uint32

	for offset < len(cea) {

		if offset+8 > len(cea) {
			break
		}

		avpCode := binary.BigEndian.Uint32(cea[offset : offset+4])
		flags := cea[offset+4]
		avpLength := (uint32(cea[offset+5]) << 16) | (uint32(cea[offset+6]) << 8) | uint32(cea[offset+7])

		dataOffset := offset + 8
		if flags&0x80 != 0 {
			dataOffset += 4
		}

		dataLength := int(avpLength) - (dataOffset - offset)
		if dataOffset+dataLength > len(cea) {
			break
		}

		data := cea[dataOffset : dataOffset+dataLength]

		switch avpCode {
		case AVP_PRODUCT_NAME:

			productName = string(data)
			if idx := strings.IndexByte(productName, 0); idx != -1 {
				productName = productName[:idx]
			}

		case AVP_FIRMWARE_REV:

			if len(data) >= 4 {
				firmwareRev = binary.BigEndian.Uint32(data[0:4])
			}
		}

		paddedLength := avpLength
		if avpLength%4 != 0 {
			paddedLength += 4 - (avpLength % 4)
		}
		offset += int(paddedLength)
	}

	if productName == "" {
		return "", 0, fmt.Errorf("Product-Name AVP not found in CEA")
	}

	return productName, firmwareRev, nil
}

// decodeFirmwareRevision decodes FreeDiameter version from Firmware-Revision AVP
func decodeFirmwareRevision(firmwareRev uint32) string {
	major := firmwareRev / 10000
	minor := (firmwareRev % 10000) / 100
	patch := firmwareRev % 100
	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
}

// identifyVendor maps Product-Name to vendor identifier for CPE
func identifyVendor(productName string) (vendor, product string) {
	productLower := strings.ToLower(productName)
	switch {
	case strings.Contains(productLower, "freediameter"):
		return "freediameter", "freediameter"
	case strings.Contains(productLower, "open5gs"):
		return "open5gs", "open5gs"
	case strings.Contains(productLower, "oracle"):
		return "oracle", "diameter"
	case strings.Contains(productLower, "ericsson"):
		return "ericsson", "diameter"
	default:
		return "*", "diameter"
	}
}

// buildCPE generates CPE 2.3 formatted string
func buildCPE(vendor, product, version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}

// ServiceDiameter contains metadata for Diameter services
type ServiceDiameter struct {
	CPEs    []string `json:"cpes,omitempty"`
	Version string   `json:"version,omitempty"`
	Vendor  string   `json:"vendor,omitempty"`
	Product string   `json:"product,omitempty"`
}

// Type implements the Metadata interface
func (s ServiceDiameter) Type() string {
	return DIAMETER
}

var defaultDIAMETERPluginPorts = probe.Ports((&DIAMETERPlugin{}).PortPriority)

func (p *DIAMETERPlugin) DefaultPorts() []int { return defaultDIAMETERPluginPorts }
func (p *DIAMETERPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
