package plugins

import (
	"encoding/binary"
	"fmt"

	"github.com/Method-Security/networkscan/generated/go/common/protocol"
)

// buildS7COTPConnectionRequest constructs an ISO 8073 Class 0 Connection
// Request inside an RFC 1006 TPKT envelope. The calling/called TSAP pair
// determines which S7 CPU family the probe targets.
//
// Wire layout (22 bytes):
//
//	TPKT:  03 00 00 16
//	COTP:  11 e0 00 00 00 01 00
//	       (length=17 follows, code=0xE0 CR, dst-ref 0, src-ref 1, class 0)
//	Param C0 01 0A  — TPDU size 1024 bytes
//	Param C1 02 <calling-TSAP>
//	Param C2 02 <called-TSAP>
//
// Named to avoid colliding with the MMS plugin's `buildCOTPConnectionRequest`
// in this same `plugins` package — MMS uses a fixed TSAP pair, S7 needs the
// variant-specific one.
func buildS7COTPConnectionRequest(pair s7TSAPPair) []byte {
	return []byte{
		// TPKT header (4 bytes)
		0x03, 0x00, 0x00, 0x16,
		// COTP CR (18 bytes)
		0x11, 0xE0,
		0x00, 0x00, // dst-ref
		0x00, 0x01, // src-ref
		0x00,             // class 0
		0xC0, 0x01, 0x0A, // TPDU size
		0xC1, 0x02, pair.calling[0], pair.calling[1], // calling TSAP
		0xC2, 0x02, pair.called[0], pair.called[1], // called TSAP
	}
}

// verifyCOTPConnectionConfirm validates a TPKT-framed COTP CC response.
// The CC PDU code is 0xD0; refusals come back as 0x80 (DR).
func verifyCOTPConnectionConfirm(resp []byte) error {
	if len(resp) < 7 {
		return fmt.Errorf("short cotp response (%d bytes)", len(resp))
	}
	// Bytes 0..3 = TPKT, byte 4 = COTP length, byte 5 = PDU code.
	switch resp[5] & 0xF0 {
	case 0xD0: // Connection Confirm
		return nil
	case 0x80: // Disconnect Request — refused
		return fmt.Errorf("cotp refused (DR 0x%02x)", resp[5])
	default:
		return fmt.Errorf("unexpected cotp pdu 0x%02x", resp[5])
	}
}

// buildS7Setup constructs a Setup Communication request. The S7 header
// declares this as a Job (type 0x01) with an 8-byte parameter block and
// no data. The S7 parameters request a negotiated PDU size of 480 bytes.
func buildS7Setup() []byte {
	return []byte{
		// TPKT header
		0x03, 0x00, 0x00, 0x19,
		// COTP DT (last data, TPDU 0)
		0x02, 0xF0, 0x80,
		// S7 header (10 bytes): protocol_id, rosctr=Job, redundancy,
		//   pdu_ref, param_len=8, data_len=0
		0x32, 0x01,
		0x00, 0x00,
		0x04, 0x00,
		0x00, 0x08,
		0x00, 0x00,
		// S7 parameters (8 bytes): function=0xF0 setup_communication,
		//   reserved, max-AMQ-calling, max-AMQ-called, PDU length 480
		0xF0, 0x00,
		0x00, 0x01,
		0x00, 0x01,
		0x01, 0xE0,
	}
}

// verifyS7SetupAck checks the Setup Communication response is a valid
// Ack-Data (rosctr=0x03) with error class 0.
func verifyS7SetupAck(resp []byte) error {
	// TPKT(4) + COTP DT(3) + S7 header (12 bytes for ack-data) = 19 min.
	if len(resp) < 19 {
		return fmt.Errorf("short setup ack (%d bytes)", len(resp))
	}
	if resp[7] != 0x32 {
		return fmt.Errorf("not S7 (proto_id 0x%02x)", resp[7])
	}
	if resp[8] != 0x03 && resp[8] != 0x02 {
		// 0x02 = Ack, 0x03 = Ack-Data. Either confirms SETUP succeeded.
		return fmt.Errorf("not an ack rosctr (got 0x%02x)", resp[8])
	}
	// Ack-Data has error class at offset 17, error code at offset 18.
	if resp[8] == 0x03 {
		if resp[17] != 0x00 || resp[18] != 0x00 {
			return fmt.Errorf("s7 setup error class=0x%02x code=0x%02x", resp[17], resp[18])
		}
	}
	return nil
}

// buildReadSZL constructs a User Data request asking the CPU for the
// system status list partial list identified by (sslID, sslIndex).
// Function group 0x4 (CPU functions), sub-function 0x4 (Read SZL).
func buildReadSZL(sslID, sslIndex uint16) []byte {
	pkt := make([]byte, 33)
	// TPKT
	pkt[0] = 0x03
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], 0x0021) // total length 33
	// COTP DT
	pkt[4] = 0x02
	pkt[5] = 0xF0
	pkt[6] = 0x80
	// S7 header — type 7 (Userdata), param_len=8, data_len=8
	pkt[7] = 0x32
	pkt[8] = 0x07
	pkt[9] = 0x00
	pkt[10] = 0x00
	binary.BigEndian.PutUint16(pkt[11:13], 0x0500) // pdu ref
	binary.BigEndian.PutUint16(pkt[13:15], 0x0008) // param len
	binary.BigEndian.PutUint16(pkt[15:17], 0x0008) // data len
	// S7 parameters (user data req header)
	pkt[17] = 0x00
	pkt[18] = 0x01
	pkt[19] = 0x12 // parameter header marker
	pkt[20] = 0x04 // following param length
	pkt[21] = 0x11 // method 0x1 request | type 0x1 request
	pkt[22] = 0x44 // function group 0x4 (CPU) | sub-function 0x4 (Read SZL)
	pkt[23] = 0x01 // sequence number
	pkt[24] = 0x00 // reserved
	// S7 data: return code OK + transport size octet + length + (sslID, sslIndex)
	pkt[25] = 0xFF
	pkt[26] = 0x09
	binary.BigEndian.PutUint16(pkt[27:29], 0x0004) // 4 bytes follow
	binary.BigEndian.PutUint16(pkt[29:31], sslID)
	binary.BigEndian.PutUint16(pkt[31:33], sslIndex)
	return pkt
}

// parseSZLResponse parses a User Data response carrying SZL records.
// Returns the slice of raw record payloads and the per-record length.
//
// Wire layout after TPKT(4) + COTP DT(3) = offset 7:
//
//	S7 header (12 bytes for Ack-Data type 0x07 Userdata response):
//	  proto_id, rosctr=0x07, redundancy[2], pdu_ref[2], param_len[2],
//	  data_len[2], error_class, error_code
//	S7 parameters (12 bytes for user data response header):
//	  00 01 12, param_len_following, method, function, seq, data_unit_ref,
//	  last_data_unit, error_code[2]
//	S7 data: ret_code(1) + transport_size(1) + len[2] + szl_header(8) + records
//	  szl_header: szl_id[2], szl_index[2], record_len[2], record_count[2]
func parseSZLResponse(resp []byte) ([][]byte, int, error) {
	if len(resp) < 31 {
		return nil, 0, fmt.Errorf("short szl response (%d bytes)", len(resp))
	}
	if resp[7] != 0x32 {
		return nil, 0, fmt.Errorf("not s7 (proto_id 0x%02x)", resp[7])
	}
	if resp[8] != 0x07 {
		return nil, 0, fmt.Errorf("not userdata rosctr (got 0x%02x)", resp[8])
	}
	paramLen := int(binary.BigEndian.Uint16(resp[13:15]))
	dataLen := int(binary.BigEndian.Uint16(resp[15:17]))
	const headerSize = 12
	paramStart := 7 + headerSize
	dataStart := paramStart + paramLen
	if dataStart+dataLen > len(resp) {
		return nil, 0, fmt.Errorf("truncated szl response (header=%d param=%d data=%d total=%d)", headerSize, paramLen, dataLen, len(resp))
	}
	// User data response has an error code at offset 10..11 of params (relative);
	// reject any non-success here.
	if paramLen >= 12 {
		errCode := binary.BigEndian.Uint16(resp[paramStart+10 : paramStart+12])
		if errCode != 0 {
			return nil, 0, fmt.Errorf("szl error 0x%04x", errCode)
		}
	}
	data := resp[dataStart : dataStart+dataLen]
	if len(data) < 12 {
		return nil, 0, fmt.Errorf("szl data too short (%d bytes)", len(data))
	}
	retCode := data[0]
	if retCode != 0xFF {
		return nil, 0, fmt.Errorf("szl ret_code 0x%02x", retCode)
	}
	szlHeader := data[4:12] // szl_id(2), szl_index(2), record_len(2), record_count(2)
	recordLen := int(binary.BigEndian.Uint16(szlHeader[4:6]))
	recordCount := int(binary.BigEndian.Uint16(szlHeader[6:8]))
	body := data[12:]
	if recordLen <= 0 || recordCount < 0 || recordLen*recordCount > len(body) {
		return nil, 0, fmt.Errorf("inconsistent szl envelope (record_len=%d count=%d body=%d)", recordLen, recordCount, len(body))
	}
	records := make([][]byte, 0, recordCount)
	for i := 0; i < recordCount; i++ {
		start := i * recordLen
		records = append(records, body[start:start+recordLen])
	}
	return records, recordLen, nil
}

// mergeSZLRecords reads SZL records and copies the relevant fields into info.
func mergeSZLRecords(info *protocol.S7CommServerInfo, sslID uint16, records [][]byte, recordLen int) {
	switch sslID {
	case 0x0011:
		mergeSZL0011(info, records, recordLen)
	case 0x001C:
		mergeSZL001C(info, records, recordLen)
	}
}

// mergeSZL0011 — Module Identification (record_len typically 28).
// Each record:
//
//	index[2], mlfb[20], bgtyp[2], ausbg[2], ausbe[2]
//
// We care about index 1 (CPU module). The MLFB is the order code; the
// firmware version is encoded as V<ausbg[0]>.<ausbg[1]>.<ausbe[1]>.
func mergeSZL0011(info *protocol.S7CommServerInfo, records [][]byte, recordLen int) {
	if recordLen < 28 {
		return
	}
	for _, rec := range records {
		if len(rec) < 28 {
			continue
		}
		index := binary.BigEndian.Uint16(rec[0:2])
		if index != 0x0001 {
			continue
		}
		mlfb := trimASCII(rec[2:22])
		if mlfb != "" && info.OrderCode == nil {
			info.OrderCode = s7StrPtr(mlfb)
		}
		ausbg := rec[24:26]
		ausbe := rec[26:28]
		version := formatS7Version(ausbg, ausbe)
		if version != "" && info.FirmwareVersion == nil {
			info.FirmwareVersion = s7StrPtr(version)
		}
		// Hardware version sometimes encoded in BGType byte 1.
		hw := rec[22:24]
		if hw[0] != 0 || hw[1] != 0 {
			if info.HardwareVersion == nil {
				info.HardwareVersion = s7StrPtr(fmt.Sprintf("0x%02x%02x", hw[0], hw[1]))
			}
		}
		return
	}
}

// formatS7Version builds the canonical "Vx.y.z" string from the two 2-byte
// firmware fields. Returns "" if the encoded version is all-zero.
func formatS7Version(ausbg, ausbe []byte) string {
	if len(ausbg) < 2 || len(ausbe) < 2 {
		return ""
	}
	// Ausbg[0]=V, Ausbg[1]=R; Ausbe[1]=A (Ausbe[0] is an ASCII space on most CPUs).
	v := ausbg[0]
	r := ausbg[1]
	a := ausbe[1]
	if v == 0 && r == 0 && a == 0 {
		return ""
	}
	if a == 0 {
		return fmt.Sprintf("V%d.%d", v, r)
	}
	return fmt.Sprintf("V%d.%d.%d", v, r, a)
}

// mergeSZL001C — Component Identification (record_len typically 34).
// Each record:
//
//	index[2], data[32 ASCII bytes]
//
// Indices per the Siemens SZL_ID 0x001C ("Identification of the component")
// specification:
//
//	1 = Name of the automation system (PLC / ASName)
//	2 = Name of the module
//	3 = Plant designation                          <- maps to plantId
//	4 = Copyright entry
//	5 = Serial number of module
//	6 = Reserved for operating system               <- skip
//	7 = Module type name (e.g. "CPU 315-2 DP")      <- maps to moduleTypeName
//	8 = Serial number of memory card                <- no field; skip
//	9 = Manufacturer / profile of a CPU module      <- no field; skip
//	A = OEM ID of a module                          <- no field; skip
//	B = Location designation of a module            <- maps to locationDesignation
//
// Previous mapping shifted 6/7/8 -> moduleTypeName/plantId/locationDesignation,
// which produced swapped/empty/misleading data on real PLCs (Bugbot AITF-103).
func mergeSZL001C(info *protocol.S7CommServerInfo, records [][]byte, recordLen int) {
	if recordLen < 34 {
		return
	}
	for _, rec := range records {
		if len(rec) < 34 {
			continue
		}
		index := binary.BigEndian.Uint16(rec[0:2])
		val := trimASCII(rec[2:34])
		if val == "" {
			continue
		}
		switch index {
		case 0x0001:
			if info.SystemName == nil {
				info.SystemName = s7StrPtr(val)
			}
		case 0x0002:
			if info.ModuleName == nil {
				info.ModuleName = s7StrPtr(val)
			}
			if info.CpuType == nil {
				info.CpuType = s7StrPtr(val)
			}
		case 0x0003:
			if info.PlantId == nil {
				info.PlantId = s7StrPtr(val)
			}
		case 0x0004:
			if info.Copyright == nil {
				info.Copyright = s7StrPtr(val)
			}
		case 0x0005:
			if info.SerialNumber == nil {
				info.SerialNumber = s7StrPtr(val)
			}
		case 0x0007:
			if info.ModuleTypeName == nil {
				info.ModuleTypeName = s7StrPtr(val)
			}
		case 0x000B:
			if info.LocationDesignation == nil {
				info.LocationDesignation = s7StrPtr(val)
			}
		}
	}
}

// trimASCII strips trailing NUL / space bytes and returns the printable prefix.
func trimASCII(b []byte) string {
	end := len(b)
	for end > 0 && (b[end-1] == 0x00 || b[end-1] == 0x20) {
		end--
	}
	out := make([]byte, 0, end)
	for _, c := range b[:end] {
		if c >= 0x20 && c < 0x7F {
			out = append(out, c)
		}
	}
	return string(out)
}
