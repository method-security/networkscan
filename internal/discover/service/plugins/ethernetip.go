package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type EthernetIPFingerprinter struct{}

func (EthernetIPFingerprinter) Name() string { return "ethernetip" }

func (EthernetIPFingerprinter) DefaultPorts() []int { return []int{44818} }

func (EthernetIPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, ethernetIPListIdentityRequest(), 1024)
	if err != nil {
		return nil, err
	}
	info, ok := parseEthernetIPIdentity(resp)
	if !ok {
		return nil, fmt.Errorf("not EtherNet/IP")
	}

	// Gate: if this is a Unitronics device, let the UniStream-specific fingerprinter own it.
	// (UniStream runs first in plugin order; we'd be re-processing if we didn't gate here.)
	vendorIDIsUnitronics := info.VendorId != nil && *info.VendorId == 318
	productNameIsUnitronics := false
	if info.ProductName != nil {
		lower := strings.ToLower(*info.ProductName)
		productNameIsUnitronics = strings.Contains(lower, "unitronics") || strings.Contains(lower, "unistream")
	}
	if vendorIDIsUnitronics || productNameIsUnitronics {
		return nil, fmt.Errorf("unitronics-specific EtherNet/IP")
	}

	// Determine version string
	version := new(string)
	if info.ProductName != nil && *info.ProductName != "" {
		*version = *info.ProductName
	} else {
		*version = "EtherNet/IP"
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeEthernetip,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Ethernetip: info},
	}, nil
}

func ethernetIPListIdentityRequest() []byte {
	return []byte{
		0x63, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
}

// parseEthernetIPIdentity parses a CIP List Identity response and returns a structured
// EthernetipServerInfo. Returns (nil, false) on any parse failure.
func parseEthernetIPIdentity(resp []byte) (*protocol.EthernetipServerInfo, bool) {
	// Validate encap header: need at least 30 bytes, command must be 0x0063
	if len(resp) < 30 || binary.LittleEndian.Uint16(resp[0:2]) != 0x0063 {
		return nil, false
	}
	length := int(binary.LittleEndian.Uint16(resp[2:4]))
	if length <= 0 || 24+length > len(resp) {
		return nil, false
	}
	// Status must be 0
	if binary.LittleEndian.Uint32(resp[8:12]) != 0 {
		return nil, false
	}

	// CPF item count at offset 24
	itemCount := int(binary.LittleEndian.Uint16(resp[24:26]))
	if itemCount < 1 || itemCount > 4 {
		return nil, false
	}

	pos := 26
	for i := 0; i < itemCount && pos+4 <= 24+length; i++ {
		itemType := binary.LittleEndian.Uint16(resp[pos : pos+2])
		itemLen := int(binary.LittleEndian.Uint16(resp[pos+2 : pos+4]))
		pos += 4
		if pos+itemLen > len(resp) {
			return nil, false
		}
		if itemType == 0x000c && itemLen >= 15 {
			data := resp[pos : pos+itemLen]
			info := parseCIPIdentityItem(data)
			return info, info != nil
		}
		pos += itemLen
	}
	return nil, false
}

// parseCIPIdentityItem parses the body of a CIP Identity item (type 0x000C).
// The data slice is the item body (after the 4-byte CPF item header).
//
// Layout (little-endian, offsets within data):
//
//	 0  2  Encap protocol version (uint16)
//	 2 16  sockaddr_in — skip
//	18  2  Vendor ID (uint16)
//	20  2  Device Type (uint16)
//	22  2  Product Code (uint16)
//	24  1  Revision major (uint8)
//	25  1  Revision minor (uint8)
//	26  2  Status (uint16)
//	28  4  Serial Number (uint32)
//	32  1  Product Name length (n)
//	33  n  Product Name string
//
// 33+n  1  State (uint8)
func parseCIPIdentityItem(data []byte) *protocol.EthernetipServerInfo {
	// We need at least 33 bytes to reach the product-name-length byte.
	if len(data) < 33 {
		return nil
	}

	encapVer := int(binary.LittleEndian.Uint16(data[0:2]))
	vendorID := binary.LittleEndian.Uint16(data[18:20])
	deviceType := binary.LittleEndian.Uint16(data[20:22])
	productCode := int(binary.LittleEndian.Uint16(data[22:24]))
	revMajor := int(data[24])
	revMinor := int(data[25])
	status := int(binary.LittleEndian.Uint16(data[26:28]))
	serial := binary.LittleEndian.Uint32(data[28:32])
	nameLen := int(data[32])

	// Bounds check: need product name bytes + 1 state byte.
	if len(data) < 33+nameLen+1 {
		return nil
	}

	productName := string(data[33 : 33+nameLen])
	state := int(data[33+nameLen])

	// Lookups
	vName := cipVendorName(vendorID)
	dtName := cipDeviceTypeName(deviceType)
	revision := fmt.Sprintf("%d.%d", revMajor, revMinor)
	serialHex := fmt.Sprintf("0x%08x", serial)

	info := &protocol.EthernetipServerInfo{
		EncapProtocolVersion: &encapVer,
		ProductCode:          &productCode,
		RevisionMajor:        &revMajor,
		RevisionMinor:        &revMinor,
		Revision:             &revision,
		Status:               &status,
		SerialNumber:         &serialHex,
		State:                &state,
	}

	vendorIDInt := int(vendorID)
	info.VendorId = &vendorIDInt
	if vName != "" {
		info.VendorName = &vName
	}

	deviceTypeInt := int(deviceType)
	info.DeviceType = &deviceTypeInt
	if dtName != "" {
		info.DeviceTypeName = &dtName
	}

	if productName != "" {
		info.ProductName = &productName
	}

	return info
}
