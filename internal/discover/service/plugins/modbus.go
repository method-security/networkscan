// Package plugins provides Modbus TCP service fingerprinting
package plugins

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

// ModbusFingerprinter performs a deep-probe Modbus TCP fingerprint using
// function 43/14 (Read Device Identification). It supersedes the vendored
// fingerprintx Modbus plugin when run inside customFingerprintModules because
// the registry is consulted first.
//
// READ-ONLY: only sends function code 0x2B (43) MEI type 0x0E.
// Write function codes (5, 6, 15, 16, 22, 23) are never issued.
type ModbusFingerprinter struct{}

func (ModbusFingerprinter) Name() string { return "modbus" }

func (ModbusFingerprinter) DefaultPorts() []int { return []int{502} }

// Modbus protocol constants
const (
	mbapHeaderLen = 7 // Transaction(2) + Protocol(2) + Length(2) + UnitID(1)

	// PDU function codes
	fcReadDeviceID  = 0x2B // Function 43: Encapsulated Interface Transport
	meiTypeDeviceID = 0x0E // MEI type 14: Read Device Identification

	// Read Device ID codes
	rdBasic   = 0x01 // Objects 0x00–0x02
	rdRegular = 0x02 // Objects 0x03–0x06

	// Exception response: function code + 0x80
	fcException = 0x80

	// Protocol ID must be 0x0000 for Modbus/TCP
	modbusProtocolID = 0x0000
)

// Detect connects to the target and attempts Modbus TCP identification.
//
// Probe sequence:
//  1. Send Basic (0x01) Read Device ID with unit ID 0xFF — fills VendorName,
//     ProductCode, MajorMinorRevision.
//  2. If Basic succeeds, send Regular (0x02) — fills VendorUrl, ProductName,
//     ModelName, UserApplicationName.
//
// If 0xFF gets an exception or connection reset, fall back to unit ID 0x01 for
// the Basic probe only.
//
// Returns a partial result (metadata with only UnitId set) even when the device
// responds with an exception to 43/14 — this still confirms a Modbus device.
func (ModbusFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	conn, err := helpers.Dial(ctx, "tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	info := &protocol.ModbusServerInfo{}

	// --- Probe 1: Basic (unit ID 0xFF) ---
	unitID := byte(0xFF)
	basicOK, basicException, err := sendReadDeviceID(conn, timeout, unitID, rdBasic, 0x00)
	if err != nil {
		// Try fallback unit ID 0x01 on any I/O error during basic probe.
		// Re-establish the connection since the first one may be dead.
		_ = conn.Close()
		conn2, err2 := helpers.Dial(ctx, "tcp", addr, timeout)
		if err2 != nil {
			return nil, fmt.Errorf("modbus: failed to connect for fallback probe: %w", err2)
		}
		defer func() { _ = conn2.Close() }()
		conn = conn2
		unitID = 0x01
		basicOK, basicException, err = sendReadDeviceID(conn, timeout, unitID, rdBasic, 0x00)
		if err != nil {
			return nil, fmt.Errorf("modbus: failed basic probe (unit 0x01): %w", err)
		}
	}

	unitIDStr := fmt.Sprintf("%d", int(unitID))
	if unitID == 0xFF {
		unitIDStr = "255"
	}
	info.UnitId = &unitIDStr

	if basicException {
		// Device is Modbus but declined 43/14 — return with just the unit ID
		return buildModbusResult(host, ip, port, info, nil), nil
	}

	if basicOK != nil {
		parseBasicObjects(basicOK, info)

		// --- Probe 2: Regular (same connection, same unit ID) ---
		if err := helpers.SetDeadline(conn, timeout); err == nil {
			regularOK, _, _ := sendReadDeviceID(conn, timeout, unitID, rdRegular, 0x03)
			if regularOK != nil {
				parseRegularObjects(regularOK, info)
			}
		}
	}

	var version *string
	if info.MajorMinorRevision != nil {
		v := *info.MajorMinorRevision
		version = &v
	}

	return buildModbusResult(host, ip, port, info, version), nil
}

// mbapPDU builds a full Modbus TCP frame (MBAP header + PDU).
// Returns the frame bytes and the transaction ID used.
func mbapPDU(unitID, functionCode, meiType, devIDCode, objectID byte) ([]byte, []byte, error) {
	txID := make([]byte, 2)
	if _, err := rand.Read(txID); err != nil {
		return nil, nil, fmt.Errorf("modbus: failed to generate transaction ID: %w", err)
	}

	// PDU: FC(1) + MEI(1) + readDevIDCode(1) + objectID(1) = 4 bytes
	pduLen := 5 // unitID(1) + PDU(4)
	frame := make([]byte, mbapHeaderLen+4)

	// MBAP header
	copy(frame[0:2], txID)                                   // Transaction ID
	binary.BigEndian.PutUint16(frame[2:4], modbusProtocolID) // Protocol ID
	binary.BigEndian.PutUint16(frame[4:6], uint16(pduLen))   // Length
	frame[6] = unitID                                        // Unit ID

	// PDU
	frame[7] = functionCode
	frame[8] = meiType
	frame[9] = devIDCode
	frame[10] = objectID

	return frame, txID, nil
}

// sendReadDeviceID sends a Read Device Identification request and reads the response.
// Returns (responseBody, isException, error):
//   - responseBody: the PDU bytes (starting after MBAP) on success; nil otherwise.
//   - isException: true when the response is a Modbus exception (0xAB) — valid Modbus, no 43/14 support.
//   - error: non-nil on I/O or protocol-framing failure.
func sendReadDeviceID(conn net.Conn, timeout int, unitID byte, devIDCode byte, objectID byte) ([]byte, bool, error) {
	frame, txID, err := mbapPDU(unitID, fcReadDeviceID, meiTypeDeviceID, devIDCode, objectID)
	if err != nil {
		return nil, false, err
	}

	if err := helpers.SetDeadline(conn, timeout); err != nil {
		return nil, false, fmt.Errorf("modbus: failed to set deadline: %w", err)
	}

	if _, err := conn.Write(frame); err != nil {
		return nil, false, fmt.Errorf("modbus: failed to send request: %w", err)
	}

	// Read MBAP header first (7 bytes)
	header := make([]byte, mbapHeaderLen)
	if _, err := readFull(conn, header); err != nil {
		return nil, false, fmt.Errorf("modbus: failed to read MBAP header: %w", err)
	}

	// Validate transaction ID echo
	if header[0] != txID[0] || header[1] != txID[1] {
		return nil, false, fmt.Errorf("modbus: transaction ID mismatch")
	}
	// Validate protocol ID
	protoID := binary.BigEndian.Uint16(header[2:4])
	if protoID != modbusProtocolID {
		return nil, false, fmt.Errorf("modbus: unexpected protocol ID 0x%04X", protoID)
	}

	// Read remaining PDU based on length field
	pduLen := int(binary.BigEndian.Uint16(header[4:6]))
	if pduLen < 1 {
		return nil, false, fmt.Errorf("modbus: PDU length too short (%d)", pduLen)
	}
	// pduLen includes unitID, so actual PDU data is pduLen-1 bytes
	pduData := make([]byte, pduLen)
	if _, err := readFull(conn, pduData); err != nil {
		return nil, false, fmt.Errorf("modbus: failed to read PDU: %w", err)
	}
	// pduData[0] is unitID (already in header[6]), pduData[1] is function code
	if len(pduData) < 2 {
		return nil, false, fmt.Errorf("modbus: PDU too short")
	}

	fc := pduData[1]
	// Exception response
	if fc == fcReadDeviceID+fcException {
		return nil, true, nil
	}
	// Unexpected function code
	if fc != fcReadDeviceID {
		return nil, false, fmt.Errorf("modbus: unexpected function code 0x%02X", fc)
	}
	// Validate MEI type
	if len(pduData) < 3 || pduData[2] != meiTypeDeviceID {
		return nil, false, fmt.Errorf("modbus: unexpected MEI type")
	}

	return pduData[1:], false, nil // strip leading unitID
}

// readFull reads exactly len(buf) bytes from conn.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// parseBasicObjects extracts device identification objects from a Basic (0x01)
// Read Device ID response PDU (starting from function code byte).
//
// PDU layout (indices relative to pdu[0] == function code):
//
//	pdu[0]  = 0x2B (function code)
//	pdu[1]  = 0x0E (MEI type)
//	pdu[2]  = readDevIDCode
//	pdu[3]  = conformityLevel
//	pdu[4]  = moreFollows
//	pdu[5]  = nextObjectID
//	pdu[6]  = numberOfObjects
//	pdu[7:] = objects (id[1] + len[1] + value[len])
func parseBasicObjects(pdu []byte, info *protocol.ModbusServerInfo) {
	if len(pdu) < 8 {
		return
	}
	conformityLevel := fmt.Sprintf("0x%02X", pdu[3])
	info.ConformityLevel = &conformityLevel

	numObjects := int(pdu[6])
	offset := 7
	for i := 0; i < numObjects && offset+1 < len(pdu); i++ {
		objID := pdu[offset]
		objLen := int(pdu[offset+1])
		offset += 2
		if offset+objLen > len(pdu) {
			break
		}
		val := string(pdu[offset : offset+objLen])
		v := val
		switch objID {
		case 0x00:
			info.VendorName = &v
		case 0x01:
			info.ProductCode = &v
		case 0x02:
			info.MajorMinorRevision = &v
		}
		offset += objLen
	}
}

// parseRegularObjects extracts device identification objects from a Regular (0x02)
// Read Device ID response PDU.
func parseRegularObjects(pdu []byte, info *protocol.ModbusServerInfo) {
	if len(pdu) < 8 {
		return
	}
	// Only update conformityLevel if not already set from basic response
	if info.ConformityLevel == nil {
		conformityLevel := fmt.Sprintf("0x%02X", pdu[3])
		info.ConformityLevel = &conformityLevel
	}

	numObjects := int(pdu[6])
	offset := 7
	for i := 0; i < numObjects && offset+1 < len(pdu); i++ {
		objID := pdu[offset]
		objLen := int(pdu[offset+1])
		offset += 2
		if offset+objLen > len(pdu) {
			break
		}
		val := string(pdu[offset : offset+objLen])
		v := val
		switch objID {
		case 0x03:
			info.VendorUrl = &v
		case 0x04:
			info.ProductName = &v
		case 0x05:
			info.ModelName = &v
		case 0x06:
			info.UserApplicationName = &v
		}
		offset += objLen
	}
}

// buildModbusResult constructs the ServiceDetails return value.
func buildModbusResult(host string, ip net.IP, port int, info *protocol.ModbusServerInfo, version *string) *discoverfern.ServiceDetails {
	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeModbus,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Modbus: info},
	}
}
