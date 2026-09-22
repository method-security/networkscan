// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol tests adapted for networkscan.
package diameter

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	readData  []byte
	writeData []byte
	readErr   error
	writeErr  error
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	n = copy(b, m.readData)
	return n, nil
}
func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// buildMockCEA creates a valid Capabilities-Exchange-Answer for testing
func buildMockCEA(productName string, firmwareRevision uint32, includeVersion bool) []byte {

	header := make([]byte, 20)

	header[0] = 1

	header[4] = 0x00

	binary.BigEndian.PutUint32(header[4:8], 257)
	header[4] = 0x00

	binary.BigEndian.PutUint32(header[8:12], 0)

	binary.BigEndian.PutUint32(header[12:16], 12345)

	binary.BigEndian.PutUint32(header[16:20], 67890)

	avps := []byte{}

	avps = append(avps, buildTestAVP(268, true, encodeTestUnsigned32(2001))...)

	avps = append(avps, buildTestAVP(264, true, []byte("test.diameter.local\x00"))...)

	avps = append(avps, buildTestAVP(296, true, []byte("local\x00"))...)

	ipAddr := []byte{0x00, 0x01, 127, 0, 0, 1}
	avps = append(avps, buildTestAVP(257, true, ipAddr)...)

	avps = append(avps, buildTestAVP(266, true, encodeTestUnsigned32(0))...)

	if productName != "" {
		productBytes := append([]byte(productName), 0x00)
		avps = append(avps, buildTestAVP(269, true, productBytes)...)
	}

	if includeVersion {
		avps = append(avps, buildTestAVP(267, false, encodeTestUnsigned32(firmwareRevision))...)
	}

	totalLength := len(header) + len(avps)

	header[1] = byte((totalLength >> 16) & 0xFF)
	header[2] = byte((totalLength >> 8) & 0xFF)
	header[3] = byte(totalLength & 0xFF)

	return append(header, avps...)
}

// buildTestAVP constructs a Diameter AVP for testing
func buildTestAVP(code uint32, mandatory bool, data []byte) []byte {

	header := make([]byte, 8)

	binary.BigEndian.PutUint32(header[0:4], code)

	flags := byte(0)
	if mandatory {
		flags |= 0x40
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

// encodeTestUnsigned32 encodes a uint32 in big-endian format for testing
func encodeTestUnsigned32(value uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return data
}

// TestPortPriority verifies that port 3868 is recognized as the default Diameter port
func TestPortPriority(t *testing.T) {
	plugin := &DIAMETERPlugin{}

	tests := []struct {
		name     string
		port     uint16
		expected bool
	}{
		{"Diameter default port", 3868, true},
		{"Non-Diameter port", 8080, false},
		{"Zero port", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.PortPriority(tt.port)
			if result != tt.expected {
				t.Errorf("PortPriority(%d) = %v, want %v", tt.port, result, tt.expected)
			}
		})
	}
}

// TestName verifies that the plugin returns "diameter" as its name
func TestName(t *testing.T) {
	plugin := &DIAMETERPlugin{}
	if plugin.Name() != "diameter" {
		t.Errorf("Name() = %s, want diameter", plugin.Name())
	}
}

// TestType verifies that the plugin returns TCP as its protocol type
func TestType(t *testing.T) {
	plugin := &DIAMETERPlugin{}
	if plugin.Type() != common.TransportTypeTcp {
		t.Errorf("Type() = %v, want plugins.TCP", plugin.Type())
	}
}

// TestPriority verifies that the plugin priority is in the expected range
func TestPriority(t *testing.T) {
	plugin := &DIAMETERPlugin{}
	priority := plugin.Priority()
	if priority < 50 || priority > 70 {
		t.Errorf("Priority() = %d, want between 50 and 70", priority)
	}
}

// TestRunWithInvalidResponse tests handling of invalid responses
func TestRunWithInvalidResponse(t *testing.T) {
	plugin := &DIAMETERPlugin{}

	tests := []struct {
		name     string
		response []byte
	}{
		{
			name:     "Empty response",
			response: []byte{},
		},
		{
			name:     "Response too short",
			response: []byte{0x01, 0x00, 0x00},
		},
		{
			name: "Invalid version",
			response: []byte{
				0x02, 0x00, 0x00, 0x14,
				0x00, 0x00, 0x01, 0x01,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x30, 0x39,
				0x00, 0x01, 0x09, 0x32,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{
				readData: tt.response,
			}

			target := helpers.Endpoint{
				Address: netip.MustParseAddrPort("127.0.0.1:3868"),
			}

			service, err := plugin.Run(conn, 5*time.Second, target)
			if err == nil {
				t.Error("Run() error = nil, want error for invalid response")
			}
			if service != nil {
				t.Errorf("Run() returned service %v, want nil for invalid response", service)
			}
		})
	}
}

// TestRunWithNonSuccessResultCode tests handling of Result-Code != 2001
func TestRunWithNonSuccessResultCode(t *testing.T) {
	plugin := &DIAMETERPlugin{}

	mockCEA := buildMockCEA("test-diameter", 0, false)

	offset := 20
	for offset < len(mockCEA)-12 {
		avpCode := binary.BigEndian.Uint32(mockCEA[offset : offset+4])
		if avpCode == 268 {

			binary.BigEndian.PutUint32(mockCEA[offset+8:offset+12], 3010)
			break
		}

		avpLength := (uint32(mockCEA[offset+5]) << 16) | (uint32(mockCEA[offset+6]) << 8) | uint32(mockCEA[offset+7])
		paddedLength := avpLength
		if avpLength%4 != 0 {
			paddedLength += 4 - (avpLength % 4)
		}
		offset += int(paddedLength)
	}

	conn := &mockConn{
		readData: mockCEA,
	}

	target := helpers.Endpoint{
		Address: netip.MustParseAddrPort("127.0.0.1:3868"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)

	if err != nil {
		t.Errorf("Run() error = %v, want nil (detection should succeed)", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil service, want valid service")
	}
	if service.Protocol != "DIAMETER" {
		t.Errorf("service.Protocol = %s, want diameter", service.Protocol)
	}
}

// TestDecodeFirmwareRevision tests the version decoding logic
func TestDecodeFirmwareRevision(t *testing.T) {
	tests := []struct {
		name             string
		firmwareRevision uint32
		expectedVersion  string
	}{
		{"Version 1.5.0", 10500, "1.5.0"},
		{"Version 1.4.0", 10400, "1.4.0"},
		{"Version 1.2.1", 10201, "1.2.1"},
		{"Version 1.0.3", 10003, "1.0.3"},
		{"Version 2.0.0", 20000, "2.0.0"},
		{"Zero version", 0, "0.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := decodeFirmwareRevision(tt.firmwareRevision)
			if version != tt.expectedVersion {
				t.Errorf("decodeFirmwareRevision(%d) = %s, want %s", tt.firmwareRevision, version, tt.expectedVersion)
			}
		})
	}
}

// TestIdentifyVendor tests vendor identification from Product-Name
func TestIdentifyVendor(t *testing.T) {
	tests := []struct {
		name            string
		productName     string
		expectedVendor  string
		expectedProduct string
	}{
		{"FreeDiameter", "freeDiameter", "freediameter", "freediameter"},
		{"Open5GS", "Open5GS", "open5gs", "open5gs"},
		{"Oracle", "Oracle Communications", "oracle", "diameter"},
		{"Ericsson", "Ericsson Diameter", "ericsson", "diameter"},
		{"Unknown", "CustomDiameter", "*", "diameter"},
		{"Empty", "", "*", "diameter"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vendor, product := identifyVendor(tt.productName)
			if vendor != tt.expectedVendor {
				t.Errorf("identifyVendor(%s) vendor = %s, want %s", tt.productName, vendor, tt.expectedVendor)
			}
			if product != tt.expectedProduct {
				t.Errorf("identifyVendor(%s) product = %s, want %s", tt.productName, product, tt.expectedProduct)
			}
		})
	}
}
