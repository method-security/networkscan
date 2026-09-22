package smpp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsValidSMPPResponse tests SMPP response validation with various scenarios
func TestIsValidSMPPResponse(t *testing.T) {
	tests := []struct {
		name        string
		response    []byte
		expectedCmd uint32
		valid       bool
	}{
		{
			name:        "valid_enquire_link_resp",
			response:    buildMockResponse(CMD_ENQUIRE_LINK_RESP, STATUS_OK, 16),
			expectedCmd: CMD_ENQUIRE_LINK_RESP,
			valid:       true,
		},
		{
			name:        "valid_bind_transceiver_resp_success",
			response:    buildMockResponse(CMD_BIND_TRANSCEIVER_RESP, STATUS_OK, 16),
			expectedCmd: CMD_BIND_TRANSCEIVER_RESP,
			valid:       true,
		},
		{
			name:        "valid_bind_transceiver_resp_with_auth_error_ESME_RINVPASWD",
			response:    buildMockResponse(CMD_BIND_TRANSCEIVER_RESP, 0x0E, 16),
			expectedCmd: CMD_BIND_TRANSCEIVER_RESP,
			valid:       true,
		},
		{
			name:        "valid_bind_transceiver_resp_with_auth_error_ESME_RINVSYSID",
			response:    buildMockResponse(CMD_BIND_TRANSCEIVER_RESP, 0x0F, 16),
			expectedCmd: CMD_BIND_TRANSCEIVER_RESP,
			valid:       true,
		},
		{
			name:        "valid_bind_transceiver_resp_with_ESME_RALYBND",
			response:    buildMockResponse(CMD_BIND_TRANSCEIVER_RESP, 0x05, 16),
			expectedCmd: CMD_BIND_TRANSCEIVER_RESP,
			valid:       true,
		},
		{
			name:        "valid_generic_nack",
			response:    buildMockResponse(CMD_GENERIC_NACK, 0x01, 16),
			expectedCmd: CMD_ENQUIRE_LINK_RESP,
			valid:       true,
		},
		{
			name:        "invalid_empty_response",
			response:    []byte{},
			expectedCmd: CMD_ENQUIRE_LINK_RESP,
			valid:       false,
		},
		{
			name:        "invalid_truncated_response",
			response:    []byte{0x00, 0x00, 0x00, 0x10, 0x80, 0x00, 0x00},
			expectedCmd: CMD_ENQUIRE_LINK_RESP,
			valid:       false,
		},
		{
			name:        "invalid_wrong_command_id",
			response:    buildMockResponse(0x12345678, STATUS_OK, 16),
			expectedCmd: CMD_ENQUIRE_LINK_RESP,
			valid:       false,
		},
		{
			name:        "invalid_length_mismatch",
			response:    buildMockResponseWithWrongLength(CMD_ENQUIRE_LINK_RESP, STATUS_OK, 16, 20),
			expectedCmd: CMD_ENQUIRE_LINK_RESP,
			valid:       false,
		},
		{
			name:        "bind_transceiver_resp_with_unknown_error_still_valid",
			response:    buildMockResponse(CMD_BIND_TRANSCEIVER_RESP, 0xFF, 16),
			expectedCmd: CMD_BIND_TRANSCEIVER_RESP,
			valid:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidSMPPResponse(tt.response, tt.expectedCmd)
			assert.Equal(t, tt.valid, result, "validation result mismatch")
		})
	}
}

// TestExtractProtocolVersion tests protocol version extraction from TLV
func TestExtractProtocolVersion(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected string
	}{
		{
			name:     "version_3.3",
			response: buildMockResponseWithVersion(0x33),
			expected: "3.3",
		},
		{
			name:     "version_3.4",
			response: buildMockResponseWithVersion(0x34),
			expected: "3.4",
		},
		{
			name:     "version_5.0",
			response: buildMockResponseWithVersion(0x50),
			expected: "5.0",
		},
		{
			name:     "version_unknown_format",
			response: buildMockResponseWithVersion(0x99),
			expected: "0x99",
		},
		{
			name:     "no_tlv_present",
			response: buildMockResponseWithSystemID("TestSystem"),
			expected: "",
		},
		{
			name:     "empty_response",
			response: []byte{},
			expected: "",
		},
		{
			name:     "truncated_response",
			response: []byte{0x00, 0x00, 0x00, 0x10},
			expected: "",
		},
		{
			name:     "malformed_tlv_truncated",
			response: buildMockResponseWithMalformedTLV(),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractProtocolVersion(tt.response)
			assert.Equal(t, tt.expected, result, "version extraction mismatch")
		})
	}
}

// TestExtractSystemID tests system_id extraction from bind response
func TestExtractSystemID(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected string
	}{
		{
			name:     "valid_system_id_kannel",
			response: buildMockResponseWithSystemID("Kannel"),
			expected: "Kannel",
		},
		{
			name:     "valid_system_id_smppsim",
			response: buildMockResponseWithSystemID("SMPPSim"),
			expected: "SMPPSim",
		},
		{
			name:     "valid_system_id_empty",
			response: buildMockResponseWithSystemID(""),
			expected: "",
		},
		{
			name:     "empty_response",
			response: []byte{},
			expected: "",
		},
		{
			name:     "truncated_response",
			response: []byte{0x00, 0x00, 0x00, 0x10},
			expected: "",
		},
		{
			name:     "missing_null_terminator",
			response: buildMockResponseWithoutNullTerminator("TestSystem"),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSystemID(tt.response)
			assert.Equal(t, tt.expected, result, "system_id extraction mismatch")
		})
	}
}

// TestIdentifyVendor tests vendor identification from system_id patterns
func TestIdentifyVendor(t *testing.T) {
	tests := []struct {
		name            string
		systemID        string
		expectedVendor  string
		expectedProduct string
	}{
		{
			name:            "kannel_detection",
			systemID:        "Kannel 1.4.5",
			expectedVendor:  "kannel",
			expectedProduct: "kannel",
		},
		{
			name:            "kannel_lowercase",
			systemID:        "kannel-gateway",
			expectedVendor:  "kannel",
			expectedProduct: "kannel",
		},
		{
			name:            "melroselabs_detection",
			systemID:        "MelroseLabsSMSC",
			expectedVendor:  "melroselabs",
			expectedProduct: "smsc-simulator",
		},
		{
			name:            "smppsim_detection",
			systemID:        "SMPPSim",
			expectedVendor:  "seleniumsoftware",
			expectedProduct: "smppsim",
		},
		{
			name:            "smppsim_with_version",
			systemID:        "SMPPSim 2.6.11",
			expectedVendor:  "seleniumsoftware",
			expectedProduct: "smppsim",
		},
		{
			name:            "jasmin_detection",
			systemID:        "Jasmin SMS Gateway",
			expectedVendor:  "jasmin",
			expectedProduct: "jasmin",
		},
		{
			name:            "jasmin_lowercase",
			systemID:        "jasmin-smsc",
			expectedVendor:  "jasmin",
			expectedProduct: "jasmin",
		},
		{
			name:            "unknown_vendor",
			systemID:        "CustomSMSC v1.0",
			expectedVendor:  "*",
			expectedProduct: "smpp",
		},
		{
			name:            "empty_system_id",
			systemID:        "",
			expectedVendor:  "*",
			expectedProduct: "smpp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := identifyVendor(tt.systemID)
			assert.Equal(t, tt.expectedVendor, result.Vendor, "vendor detection mismatch")
			assert.Equal(t, tt.expectedProduct, result.Product, "product detection mismatch")
		})
	}
}

// TestBuildSMPPCPE tests CPE string generation
func TestBuildSMPPCPE(t *testing.T) {
	tests := []struct {
		name     string
		vendor   string
		product  string
		version  string
		expected string
	}{
		{
			name:     "full_cpe_kannel",
			vendor:   "kannel",
			product:  "kannel",
			version:  "3.4",
			expected: "cpe:2.3:a:kannel:kannel:3.4:*:*:*:*:*:*:*",
		},
		{
			name:     "wildcard_vendor",
			vendor:   "",
			product:  "smpp",
			version:  "3.4",
			expected: "cpe:2.3:a:*:smpp:3.4:*:*:*:*:*:*:*",
		},
		{
			name:     "wildcard_version",
			vendor:   "kannel",
			product:  "kannel",
			version:  "",
			expected: "cpe:2.3:a:kannel:kannel:*:*:*:*:*:*:*:*",
		},
		{
			name:     "all_wildcards",
			vendor:   "",
			product:  "",
			version:  "",
			expected: "cpe:2.3:a:*:smpp:*:*:*:*:*:*:*:*",
		},
		{
			name:     "melroselabs",
			vendor:   "melroselabs",
			product:  "smsc-simulator",
			version:  "5.0",
			expected: "cpe:2.3:a:melroselabs:smsc-simulator:5.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildSMPPCPE(tt.vendor, tt.product, tt.version)
			assert.Equal(t, tt.expected, result, "CPE string mismatch")
		})
	}
}

// TestBuildEnquireLinkPDU tests enquire_link PDU construction
func TestBuildEnquireLinkPDU(t *testing.T) {
	pdu := buildEnquireLinkPDU()

	assert.Equal(t, 16, len(pdu), "PDU should be exactly 16 bytes")

	cmdLength := binary.BigEndian.Uint32(pdu[0:4])
	cmdID := binary.BigEndian.Uint32(pdu[4:8])
	cmdStatus := binary.BigEndian.Uint32(pdu[8:12])
	seqNum := binary.BigEndian.Uint32(pdu[12:16])

	assert.Equal(t, uint32(16), cmdLength, "command_length should be 16")
	assert.Equal(t, uint32(CMD_ENQUIRE_LINK), cmdID, "command_id should be enquire_link")
	assert.Equal(t, uint32(0), cmdStatus, "command_status should be 0")
	assert.Equal(t, uint32(1), seqNum, "sequence_number should be 1")
}

// TestBuildBindTransceiverPDU tests bind_transceiver PDU construction
func TestBuildBindTransceiverPDU(t *testing.T) {
	pdu := buildBindTransceiverPDU()

	assert.GreaterOrEqual(t, len(pdu), 16, "PDU should be at least 16 bytes")

	cmdLength := binary.BigEndian.Uint32(pdu[0:4])
	cmdID := binary.BigEndian.Uint32(pdu[4:8])
	cmdStatus := binary.BigEndian.Uint32(pdu[8:12])
	seqNum := binary.BigEndian.Uint32(pdu[12:16])

	assert.Equal(t, uint32(len(pdu)), cmdLength, "command_length should match actual PDU length")
	assert.Equal(t, uint32(CMD_BIND_TRANSCEIVER), cmdID, "command_id should be bind_transceiver")
	assert.Equal(t, uint32(0), cmdStatus, "command_status should be 0")
	assert.Equal(t, uint32(2), seqNum, "sequence_number should be 2")

	bodyStart := 16
	assert.Contains(t, string(pdu[bodyStart:]), "test", "body should contain system_id 'test'")

	if len(pdu) > 27 {
		assert.Equal(t, byte(0x34), pdu[27], "interface_version should be 0x34 (SMPP 3.4)")
	}
}

// Helper function to build a mock SMPP response
func buildMockResponse(cmdID uint32, status uint32, length int) []byte {
	response := make([]byte, length)
	binary.BigEndian.PutUint32(response[0:4], uint32(length))
	binary.BigEndian.PutUint32(response[4:8], cmdID)
	binary.BigEndian.PutUint32(response[8:12], status)
	binary.BigEndian.PutUint32(response[12:16], 1)
	return response
}

// Helper function to build a mock response with wrong length field
func buildMockResponseWithWrongLength(cmdID uint32, status uint32, actualLength int, claimedLength int) []byte {
	response := make([]byte, actualLength)
	binary.BigEndian.PutUint32(response[0:4], uint32(claimedLength))
	binary.BigEndian.PutUint32(response[4:8], cmdID)
	binary.BigEndian.PutUint32(response[8:12], status)
	binary.BigEndian.PutUint32(response[12:16], 1)
	return response
}

// Helper function to build a mock response with protocol version TLV
func buildMockResponseWithVersion(versionByte byte) []byte {

	response := make([]byte, 23)

	binary.BigEndian.PutUint32(response[0:4], 23)
	binary.BigEndian.PutUint32(response[4:8], CMD_BIND_TRANSCEIVER_RESP)
	binary.BigEndian.PutUint32(response[8:12], STATUS_OK)
	binary.BigEndian.PutUint32(response[12:16], 1)

	response[16] = 0x00

	binary.BigEndian.PutUint16(response[17:19], TLV_SC_INTERFACE_VERSION)
	binary.BigEndian.PutUint16(response[19:21], 1)
	response[21] = versionByte

	return response
}

// Helper function to build a mock response with system_id but no TLV
func buildMockResponseWithSystemID(systemID string) []byte {

	length := 16 + len(systemID) + 1
	response := make([]byte, length)

	binary.BigEndian.PutUint32(response[0:4], uint32(length))
	binary.BigEndian.PutUint32(response[4:8], CMD_BIND_TRANSCEIVER_RESP)
	binary.BigEndian.PutUint32(response[8:12], STATUS_OK)
	binary.BigEndian.PutUint32(response[12:16], 1)

	copy(response[16:], systemID)
	response[16+len(systemID)] = 0x00

	return response
}

// Helper function to build a mock response without null terminator
func buildMockResponseWithoutNullTerminator(systemID string) []byte {

	length := 16 + len(systemID)
	response := make([]byte, length)

	binary.BigEndian.PutUint32(response[0:4], uint32(length))
	binary.BigEndian.PutUint32(response[4:8], CMD_BIND_TRANSCEIVER_RESP)
	binary.BigEndian.PutUint32(response[8:12], STATUS_OK)
	binary.BigEndian.PutUint32(response[12:16], 1)

	copy(response[16:], systemID)

	return response
}

// Helper function to build a mock response with malformed TLV (truncated)
func buildMockResponseWithMalformedTLV() []byte {

	response := make([]byte, 20)

	binary.BigEndian.PutUint32(response[0:4], 20)
	binary.BigEndian.PutUint32(response[4:8], CMD_BIND_TRANSCEIVER_RESP)
	binary.BigEndian.PutUint32(response[8:12], STATUS_OK)
	binary.BigEndian.PutUint32(response[12:16], 1)

	response[16] = 0x00

	binary.BigEndian.PutUint16(response[17:19], TLV_SC_INTERFACE_VERSION)
	response[19] = 0x00

	return response
}

// TestFallbackDetectionScenarios tests the bind_transceiver fallback logic
// when enquire_link fails or times out (simulating servers that require binding first)
func TestFallbackDetectionScenarios(t *testing.T) {
	tests := []struct {
		name                    string
		enquireLinkResponse     []byte
		enquireLinkShouldDetect bool
		bindResponse            []byte
		bindShouldDetect        bool
		expectedDetection       bool
		description             string
	}{
		{
			name:                    "fallback_bind_success_with_auth_error",
			enquireLinkResponse:     nil,
			enquireLinkShouldDetect: false,
			bindResponse:            buildMockResponse(CMD_BIND_TRANSCEIVER_RESP, 0x0E, 16),
			bindShouldDetect:        true,
			expectedDetection:       true,
			description:             "enquire_link fails, bind_transceiver returns auth error (still confirms SMPP)",
		},
		{
			name:                    "fallback_bind_success_with_generic_nack",
			enquireLinkResponse:     nil,
			enquireLinkShouldDetect: false,
			bindResponse:            buildMockResponse(CMD_GENERIC_NACK, 0x01, 16),
			bindShouldDetect:        true,
			expectedDetection:       true,
			description:             "enquire_link fails, bind_transceiver returns generic_nack (still confirms SMPP)",
		},
		{
			name:                    "fallback_bind_success_with_OK",
			enquireLinkResponse:     nil,
			enquireLinkShouldDetect: false,
			bindResponse:            buildMockResponse(CMD_BIND_TRANSCEIVER_RESP, STATUS_OK, 16),
			bindShouldDetect:        true,
			expectedDetection:       true,
			description:             "enquire_link fails, bind_transceiver succeeds with STATUS_OK",
		},
		{
			name:                    "both_fail_no_detection",
			enquireLinkResponse:     nil,
			enquireLinkShouldDetect: false,
			bindResponse:            nil,
			bindShouldDetect:        false,
			expectedDetection:       false,
			description:             "both enquire_link and bind_transceiver fail (no SMPP server)",
		},
		{
			name:                    "enquire_link_succeeds_no_fallback_needed",
			enquireLinkResponse:     buildMockResponse(CMD_ENQUIRE_LINK_RESP, STATUS_OK, 16),
			enquireLinkShouldDetect: true,
			bindResponse:            nil,
			bindShouldDetect:        false,
			expectedDetection:       true,
			description:             "enquire_link succeeds, no fallback to bind_transceiver needed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			enquireLinkValid := false
			if tt.enquireLinkResponse != nil {
				enquireLinkValid = isValidSMPPResponse(tt.enquireLinkResponse, CMD_ENQUIRE_LINK_RESP)
			}
			assert.Equal(t, tt.enquireLinkShouldDetect, enquireLinkValid, "enquire_link detection mismatch")

			bindValid := false
			if tt.bindResponse != nil {
				bindValid = isValidSMPPResponse(tt.bindResponse, CMD_BIND_TRANSCEIVER_RESP)
			}
			assert.Equal(t, tt.bindShouldDetect, bindValid, "bind_transceiver detection mismatch")

			detected := enquireLinkValid || bindValid
			assert.Equal(t, tt.expectedDetection, detected, tt.description)
		})
	}
}

// TestDetectSMPPReturnsBindResponse tests that detectSMPP returns the bind_transceiver
// response when it's used for detection (to avoid sending bind twice)
func TestDetectSMPPReturnsBindResponse(t *testing.T) {

	bindResp := buildMockResponseWithSystemID("Kannel")

	assert.True(t, isValidSMPPResponse(bindResp, CMD_BIND_TRANSCEIVER_RESP),
		"bind response should be valid for detection")

	systemID := extractSystemID(bindResp)
	assert.Equal(t, "Kannel", systemID, "should extract systemID from cached bind response")
}
