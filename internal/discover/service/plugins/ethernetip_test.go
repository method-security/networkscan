package plugins

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildIdentityResponse builds a complete CIP List Identity response with the given parameters.
// It produces: EtherNet/IP encap header (24 bytes) + CPF header (4 bytes) +
// Identity item header (4 bytes) + Identity item body.
func buildIdentityResponse(vendorID, deviceType, productCode uint16, revMajor, revMinor uint8, status uint16, serial uint32, productName string, state uint8) []byte {
	nameLen := len(productName)

	// Identity item body layout:
	//  0  2  Encap protocol version
	//  2 16  sockaddr_in (zero-filled)
	// 18  2  Vendor ID
	// 20  2  Device Type
	// 22  2  Product Code
	// 24  1  Rev major
	// 25  1  Rev minor
	// 26  2  Status
	// 28  4  Serial Number
	// 32  1  Product Name length
	// 33  n  Product Name
	// 33+n 1  State
	itemBodyLen := 33 + nameLen + 1
	itemBody := make([]byte, itemBodyLen)

	binary.LittleEndian.PutUint16(itemBody[0:2], 1) // encap protocol version = 1
	// bytes 2-17 are sockaddr_in — leave as zero
	binary.LittleEndian.PutUint16(itemBody[18:20], vendorID)
	binary.LittleEndian.PutUint16(itemBody[20:22], deviceType)
	binary.LittleEndian.PutUint16(itemBody[22:24], productCode)
	itemBody[24] = revMajor
	itemBody[25] = revMinor
	binary.LittleEndian.PutUint16(itemBody[26:28], status)
	binary.LittleEndian.PutUint32(itemBody[28:32], serial)
	itemBody[32] = byte(nameLen)
	copy(itemBody[33:33+nameLen], productName)
	itemBody[33+nameLen] = state

	// CPF item header: type (2 bytes) + length (2 bytes)
	itemHeader := make([]byte, 4)
	binary.LittleEndian.PutUint16(itemHeader[0:2], 0x000c) // Identity item type
	binary.LittleEndian.PutUint16(itemHeader[2:4], uint16(itemBodyLen))

	// CPF wrapper: item count (2 bytes) + item header + item body
	cpfItemCount := make([]byte, 2)
	binary.LittleEndian.PutUint16(cpfItemCount, 1)

	cpfPayload := append(cpfItemCount, itemHeader...)
	cpfPayload = append(cpfPayload, itemBody...)

	// EtherNet/IP encap header (24 bytes):
	//  0  2  Command (0x0063)
	//  2  2  Length (CPF payload length)
	//  4  4  Session handle (0)
	//  8  4  Status (0)
	// 12  8  Sender context (0)
	// 20  4  Options (0)
	encapHeader := make([]byte, 24)
	binary.LittleEndian.PutUint16(encapHeader[0:2], 0x0063)
	binary.LittleEndian.PutUint16(encapHeader[2:4], uint16(len(cpfPayload)))

	return append(encapHeader, cpfPayload...)
}

func TestParseEthernetIPIdentity_Rockwell(t *testing.T) {
	// Vendor 1 = Rockwell Automation/Allen-Bradley, device type 0x000E (PLC)
	// product code 65, revision 1.2, serial 0x12345678, product name "1756-EN2T/D", state 3
	resp := buildIdentityResponse(1, 0x000E, 65, 1, 2, 96, 0x12345678, "1756-EN2T/D", 3)

	info, ok := parseEthernetIPIdentity(resp)
	if !ok || info == nil {
		t.Fatal("expected ok=true and non-nil info")
	}

	if info.VendorId == nil || *info.VendorId != 1 {
		t.Errorf("expected vendorId=1, got %v", info.VendorId)
	}
	if info.VendorName == nil || *info.VendorName != "Rockwell Automation/Allen-Bradley" {
		t.Errorf("expected vendorName='Rockwell Automation/Allen-Bradley', got %v", info.VendorName)
	}
	if info.DeviceType == nil || *info.DeviceType != 0x000E {
		t.Errorf("expected deviceType=0x000E, got %v", info.DeviceType)
	}
	if info.DeviceTypeName == nil || *info.DeviceTypeName != "PLC" {
		t.Errorf("expected deviceTypeName='PLC', got %v", info.DeviceTypeName)
	}
	if info.ProductCode == nil || *info.ProductCode != 65 {
		t.Errorf("expected productCode=65, got %v", info.ProductCode)
	}
	if info.ProductName == nil || *info.ProductName != "1756-EN2T/D" {
		t.Errorf("expected productName='1756-EN2T/D', got %v", info.ProductName)
	}
	if info.RevisionMajor == nil || *info.RevisionMajor != 1 {
		t.Errorf("expected revisionMajor=1, got %v", info.RevisionMajor)
	}
	if info.RevisionMinor == nil || *info.RevisionMinor != 2 {
		t.Errorf("expected revisionMinor=2, got %v", info.RevisionMinor)
	}
	if info.Revision == nil || *info.Revision != "1.2" {
		t.Errorf("expected revision='1.2', got %v", info.Revision)
	}
	if info.Status == nil || *info.Status != 96 {
		t.Errorf("expected status=96, got %v", info.Status)
	}
	if info.SerialNumber == nil || *info.SerialNumber != "0x12345678" {
		t.Errorf("expected serialNumber='0x12345678', got %v", info.SerialNumber)
	}
	if info.State == nil || *info.State != 3 {
		t.Errorf("expected state=3, got %v", info.State)
	}
	if info.EncapProtocolVersion == nil || *info.EncapProtocolVersion != 1 {
		t.Errorf("expected encapProtocolVersion=1, got %v", info.EncapProtocolVersion)
	}
}

func TestParseEthernetIPIdentity_OMRON(t *testing.T) {
	// Vendor 47 = OMRON Corporation
	resp := buildIdentityResponse(47, 0x000E, 100, 2, 0, 0, 0xABCDEF01, "NX-ECC201", 3)

	info, ok := parseEthernetIPIdentity(resp)
	if !ok || info == nil {
		t.Fatal("expected ok=true and non-nil info")
	}

	if info.VendorId == nil || *info.VendorId != 47 {
		t.Errorf("expected vendorId=47, got %v", info.VendorId)
	}
	if info.VendorName == nil || *info.VendorName != "OMRON Corporation" {
		t.Errorf("expected vendorName='OMRON Corporation', got %v", info.VendorName)
	}
}

func TestParseEthernetIPIdentity_UnitronicsVendorID(t *testing.T) {
	// Vendor 318 = Unitronics — parser should succeed, but Detect should return (nil, err)
	resp := buildIdentityResponse(318, 0x000E, 1, 1, 0, 0, 0x00000001, "UniStream-US5", 3)

	info, ok := parseEthernetIPIdentity(resp)
	if !ok || info == nil {
		t.Fatal("expected parser to succeed for Unitronics response")
	}

	if info.VendorId == nil || *info.VendorId != 318 {
		t.Errorf("expected vendorId=318, got %v", info.VendorId)
	}

	// Verify that the Detect-level Unitronics gate fires on vendor ID 318
	vendorIDIsUnitronics := info.VendorId != nil && *info.VendorId == 318
	if !vendorIDIsUnitronics {
		t.Error("expected vendorId 318 to trigger Unitronics gate in Detect")
	}
}

func TestParseEthernetIPIdentity_UnitronicsProductName(t *testing.T) {
	// Product name contains "unistream" — Detect-level gate should also fire on name
	resp := buildIdentityResponse(9999, 0x000E, 1, 1, 0, 0, 0x00000001, "UniStream PLC", 3)

	info, ok := parseEthernetIPIdentity(resp)
	if !ok || info == nil {
		t.Fatal("expected parser to succeed")
	}

	// Vendor is NOT 318
	if info.VendorId != nil && *info.VendorId == 318 {
		t.Error("expected vendor != 318 for this test case")
	}

	// Verify product name gate would trigger
	productNameIsUnitronics := false
	if info.ProductName != nil {
		lower := strings.ToLower(*info.ProductName)
		productNameIsUnitronics = strings.Contains(lower, "unitronics") || strings.Contains(lower, "unistream")
	}
	if !productNameIsUnitronics {
		t.Errorf("expected product name 'UniStream PLC' to trigger Unitronics gate, productName=%v", info.ProductName)
	}
}

func TestParseEthernetIPIdentity_TruncatedResponse(t *testing.T) {
	// Build a valid response first, then truncate it mid-product-name
	resp := buildIdentityResponse(1, 0x000E, 65, 1, 2, 96, 0x12345678, "1756-EN2T/D", 3)

	// Truncate to cut off within the identity item body.
	// The encap header is 24 bytes, CPF count 2 bytes, item header 4 bytes = 30 bytes before item body.
	// Cut after 35 bytes total (only 5 bytes of item body) — not enough to reach offset 33.
	truncated := resp[:35]

	info, ok := parseEthernetIPIdentity(truncated)
	// Should return (nil, false) without panicking
	if ok || info != nil {
		t.Errorf("expected (nil, false) for truncated response, got ok=%v info=%v", ok, info)
	}
}

func TestParseEthernetIPIdentity_UnknownVendor(t *testing.T) {
	// Vendor 9999 is not in the table — vendorName should be nil, vendorId should be set
	resp := buildIdentityResponse(9999, 0x000C, 0, 1, 0, 0, 0, "Unknown Device", 0)

	info, ok := parseEthernetIPIdentity(resp)
	if !ok || info == nil {
		t.Fatal("expected ok=true and non-nil info for unknown vendor")
	}
	if info.VendorId == nil || *info.VendorId != 9999 {
		t.Errorf("expected vendorId=9999, got %v", info.VendorId)
	}
	if info.VendorName != nil {
		t.Errorf("expected vendorName=nil for unknown vendor, got %v", *info.VendorName)
	}
	if info.DeviceTypeName == nil || *info.DeviceTypeName != "Communications Adapter" {
		t.Errorf("expected deviceTypeName='Communications Adapter', got %v", info.DeviceTypeName)
	}
}
