// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted for networkscan; see ../NOTICE.md.

package smpp

import (
	"bytes"
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
	SMPP                      = "smpp"
	MIN_RESPONSE_SIZE         = 16
	PDU_HEADER_SIZE           = 16
	CMD_ENQUIRE_LINK          = 0x00000015
	CMD_ENQUIRE_LINK_RESP     = 0x80000015
	CMD_BIND_TRANSCEIVER      = 0x00000009
	CMD_BIND_TRANSCEIVER_RESP = 0x80000009
	CMD_GENERIC_NACK          = 0x80000000
	STATUS_OK                 = 0x00000000
	TLV_SC_INTERFACE_VERSION  = 0x0210
)

type SMPPPlugin struct{}

// VendorInfo holds detected vendor and product information
type VendorInfo struct {
	Vendor  string
	Product string
}

func (p *SMPPPlugin) PortPriority(port uint16) bool {
	return port == 2775 || port == 2776
}
func (p *SMPPPlugin) Name() string {
	return SMPP
}
func (p *SMPPPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *SMPPPlugin) Priority() int {
	return 55
}
func (p *SMPPPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {

	isValid, cachedBindResp, err := detectSMPP(conn, timeout)
	if err != nil || !isValid {
		return nil, nil
	}

	version, systemID, vendorInfo := enrichSMPP(conn, timeout, cachedBindResp)

	cpe := buildSMPPCPE(vendorInfo.Vendor, vendorInfo.Product, version)
	cpes := []string{}
	if cpe != "" {
		cpes = append(cpes, cpe)
	}

	payload := probe.ServiceSMPP{
		CPEs:            cpes,
		ProtocolVersion: version,
		SystemID:        systemID,
		Vendor:          vendorInfo.Vendor,
		Product:         vendorInfo.Product,
	}

	return probe.Result(target, payload, false, version, probe.TCP), nil
}

// detectSMPP performs Phase 1 detection with fallback strategy
// Returns: (detected bool, cachedBindResponse []byte, error)
//
// Phase 1a: Try enquire_link first (preferred method)
// Phase 1b: If enquire_link fails, try bind_transceiver as fallback
//
// Some SMPP servers only respond to enquire_link after binding (non-standard behavior).
// The fallback ensures detection succeeds even on these servers.
// If bind_transceiver is used for detection, the response is cached to avoid resending during enrichment.
func detectSMPP(conn net.Conn, timeout time.Duration) (bool, []byte, error) {

	enquireLinkPDU := buildEnquireLinkPDU()
	response, err := utils.SendRecv(conn, enquireLinkPDU, timeout)

	if err == nil && isValidSMPPResponse(response, CMD_ENQUIRE_LINK_RESP) {
		return true, nil, nil
	}

	bindPDU := buildBindTransceiverPDU()
	bindResponse, bindErr := utils.SendRecv(conn, bindPDU, timeout)
	if bindErr != nil {

		return false, nil, bindErr
	}

	if isValidSMPPResponse(bindResponse, CMD_BIND_TRANSCEIVER_RESP) {

		return true, bindResponse, nil
	}

	return false, nil, &utils.InvalidResponseError{Service: SMPP}
}

// enrichSMPP performs Phase 2 enrichment using bind_transceiver
// Returns: (version, systemID, vendorInfo)
//
// If cachedBindResp is provided (from fallback detection), reuse it to avoid resending bind_transceiver.
// Otherwise, send a new bind_transceiver request for enrichment.
func enrichSMPP(conn net.Conn, timeout time.Duration, cachedBindResp []byte) (string, string, VendorInfo) {
	var response []byte

	if len(cachedBindResp) >= MIN_RESPONSE_SIZE {
		response = cachedBindResp
	} else {

		bindPDU := buildBindTransceiverPDU()
		var err error
		response, err = utils.SendRecv(conn, bindPDU, timeout)
		if err != nil || len(response) < MIN_RESPONSE_SIZE {

			return "", "", VendorInfo{Vendor: "*", Product: "smpp"}
		}
	}

	version := extractProtocolVersion(response)
	systemID := extractSystemID(response)
	vendorInfo := identifyVendor(systemID)

	if version == "" && isValidSMPPResponse(response, CMD_BIND_TRANSCEIVER_RESP) {
		version = "3.4"
	}

	return version, systemID, vendorInfo
}

// buildEnquireLinkPDU creates an enquire_link PDU (16 bytes, header only)
func buildEnquireLinkPDU() []byte {
	pdu := make([]byte, 16)
	binary.BigEndian.PutUint32(pdu[0:4], 16)
	binary.BigEndian.PutUint32(pdu[4:8], CMD_ENQUIRE_LINK)
	binary.BigEndian.PutUint32(pdu[8:12], 0)
	binary.BigEndian.PutUint32(pdu[12:16], 1)
	return pdu
}

// buildBindTransceiverPDU creates a bind_transceiver PDU with dummy credentials
func buildBindTransceiverPDU() []byte {

	systemID := "test\x00"
	password := "test\x00"
	systemType := "\x00"
	interfaceVersion := byte(0x34)
	addrTON := byte(0)
	addrNPI := byte(0)
	addressRange := "\x00"

	body := []byte(systemID + password + systemType)
	body = append(body, interfaceVersion, addrTON, addrNPI)
	body = append(body, []byte(addressRange)...)

	pduLen := PDU_HEADER_SIZE + len(body)
	pdu := make([]byte, pduLen)

	binary.BigEndian.PutUint32(pdu[0:4], uint32(pduLen))
	binary.BigEndian.PutUint32(pdu[4:8], CMD_BIND_TRANSCEIVER)
	binary.BigEndian.PutUint32(pdu[8:12], 0)
	binary.BigEndian.PutUint32(pdu[12:16], 2)

	copy(pdu[16:], body)

	return pdu
}

// isValidSMPPResponse validates SMPP response structure
func isValidSMPPResponse(response []byte, expectedCmdID uint32) bool {

	if len(response) < MIN_RESPONSE_SIZE {
		return false
	}

	cmdLength := binary.BigEndian.Uint32(response[0:4])
	cmdID := binary.BigEndian.Uint32(response[4:8])
	cmdStatus := binary.BigEndian.Uint32(response[8:12])

	if cmdLength != uint32(len(response)) {
		return false
	}

	if cmdID == expectedCmdID {
		return true
	}

	if cmdID == CMD_GENERIC_NACK {
		return true
	}

	if expectedCmdID == CMD_BIND_TRANSCEIVER_RESP && cmdID == CMD_BIND_TRANSCEIVER_RESP {

		if cmdStatus == 0x0E || cmdStatus == 0x0F || cmdStatus == 0x05 || cmdStatus == STATUS_OK {
			return true
		}
	}

	return false
}

// extractProtocolVersion extracts protocol version from sc_interface_version TLV
func extractProtocolVersion(response []byte) string {
	if len(response) < MIN_RESPONSE_SIZE {
		return ""
	}

	bodyStart := PDU_HEADER_SIZE

	pos := bodyStart
	for pos < len(response) && response[pos] != 0 {
		pos++
	}
	pos++

	for pos+4 <= len(response) {
		tag := binary.BigEndian.Uint16(response[pos : pos+2])
		length := binary.BigEndian.Uint16(response[pos+2 : pos+4])

		if tag == TLV_SC_INTERFACE_VERSION && length == 1 && pos+4+int(length) <= len(response) {
			versionByte := response[pos+4]

			switch versionByte {
			case 0x33:
				return "3.3"
			case 0x34:
				return "3.4"
			case 0x50:
				return "5.0"
			default:
				return fmt.Sprintf("0x%02x", versionByte)
			}
		}

		pos += 4 + int(length)
	}

	return ""
}

// extractSystemID extracts system_id from bind_transceiver_resp
func extractSystemID(response []byte) string {
	if len(response) < MIN_RESPONSE_SIZE {
		return ""
	}

	bodyStart := PDU_HEADER_SIZE
	endPos := bytes.IndexByte(response[bodyStart:], 0)
	if endPos == -1 {
		return ""
	}

	systemID := string(response[bodyStart : bodyStart+endPos])
	return systemID
}

// identifyVendor identifies vendor and product from system_id
func identifyVendor(systemID string) VendorInfo {
	if systemID == "" {
		return VendorInfo{Vendor: "*", Product: "smpp"}
	}

	sysIDLower := strings.ToLower(systemID)

	if strings.Contains(sysIDLower, "kannel") {
		return VendorInfo{Vendor: "kannel", Product: "kannel"}
	}
	if strings.Contains(sysIDLower, "melroselabssmsc") {
		return VendorInfo{Vendor: "melroselabs", Product: "smsc-simulator"}
	}
	if strings.Contains(sysIDLower, "smppsim") {
		return VendorInfo{Vendor: "seleniumsoftware", Product: "smppsim"}
	}
	if strings.Contains(sysIDLower, "jasmin") {
		return VendorInfo{Vendor: "jasmin", Product: "jasmin"}
	}

	return VendorInfo{Vendor: "*", Product: "smpp"}
}

// buildSMPPCPE generates a CPE (Common Platform Enumeration) string for SMPP servers
// Format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
func buildSMPPCPE(vendor, product, version string) string {
	if vendor == "" {
		vendor = "*"
	}
	if product == "" {
		product = "smpp"
	}
	if version == "" {
		version = "*"
	}

	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}

var defaultSMPPPluginPorts = probe.Ports((&SMPPPlugin{}).PortPriority)

func (p *SMPPPlugin) DefaultPorts() []int { return defaultSMPPPluginPorts }
func (p *SMPPPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
