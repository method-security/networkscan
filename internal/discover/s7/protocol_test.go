package s7

import (
	"encoding/binary"
	"testing"

	"github.com/Method-Security/networkscan/generated/go/common/protocol"
)

func TestBuildCOTPConnectionRequestLengthAndTSAP(t *testing.T) {
	cr := buildCOTPConnectionRequest(tsapS7_1500)
	if len(cr) != 22 {
		t.Fatalf("want 22 bytes, got %d", len(cr))
	}
	if cr[0] != 0x03 || cr[1] != 0x00 {
		t.Fatalf("bad TPKT version %x %x", cr[0], cr[1])
	}
	if binary.BigEndian.Uint16(cr[2:4]) != 22 {
		t.Fatalf("bad TPKT len: %d", binary.BigEndian.Uint16(cr[2:4]))
	}
	if cr[4] != 0x11 || cr[5] != 0xE0 {
		t.Fatalf("bad COTP CR header: %x %x", cr[4], cr[5])
	}
	// Calling TSAP at offset 16..17, called at 20..21
	if cr[16] != 0x02 || cr[17] != 0x00 {
		t.Fatalf("wrong calling TSAP: %x %x", cr[16], cr[17])
	}
	if cr[20] != 0x03 || cr[21] != 0x00 {
		t.Fatalf("wrong called TSAP: %x %x", cr[20], cr[21])
	}
}

func TestVerifyCOTPConnectionConfirm(t *testing.T) {
	// Real-shape CC bytes: TPKT(03 00 00 16) + COTP(11 D0 …)
	ok := []byte{0x03, 0x00, 0x00, 0x16, 0x11, 0xD0, 0x00}
	if err := verifyCOTPConnectionConfirm(ok); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	dr := []byte{0x03, 0x00, 0x00, 0x16, 0x11, 0x80, 0x00}
	if err := verifyCOTPConnectionConfirm(dr); err == nil {
		t.Fatal("expected refused error")
	}
	short := []byte{0x03, 0x00, 0x00, 0x04}
	if err := verifyCOTPConnectionConfirm(short); err == nil {
		t.Fatal("expected short error")
	}
}

func TestBuildS7SetupShape(t *testing.T) {
	pkt := buildS7Setup()
	if len(pkt) != 25 {
		t.Fatalf("want 25 bytes, got %d", len(pkt))
	}
	if pkt[7] != 0x32 || pkt[8] != 0x01 {
		t.Fatalf("bad S7 header proto/type: %x %x", pkt[7], pkt[8])
	}
	if binary.BigEndian.Uint16(pkt[13:15]) != 0x0008 {
		t.Fatalf("param length should be 8")
	}
	if pkt[17] != 0xF0 {
		t.Fatalf("setup function byte should be 0xF0, got 0x%02x", pkt[17])
	}
}

func TestVerifyS7SetupAck(t *testing.T) {
	// Build a TPKT(4) + COTP DT(3) + S7 Ack-Data header (12 bytes) — total 19.
	resp := make([]byte, 19)
	resp[0] = 0x03
	resp[1] = 0x00
	binary.BigEndian.PutUint16(resp[2:4], 19)
	resp[4] = 0x02
	resp[5] = 0xF0
	resp[6] = 0x80
	resp[7] = 0x32 // proto
	resp[8] = 0x03 // ack-data
	// rest zero -> error class/code 0 -> ok
	if err := verifyS7SetupAck(resp); err != nil {
		t.Fatalf("want ok, got %v", err)
	}
	// Inject an error class.
	resp[17] = 0x85
	if err := verifyS7SetupAck(resp); err == nil {
		t.Fatal("want error class detection")
	}
}

func TestBuildReadSZLEncodesIDAndIndex(t *testing.T) {
	pkt := buildReadSZL(0x0011, 0x0000)
	if len(pkt) != 33 {
		t.Fatalf("want 33 bytes, got %d", len(pkt))
	}
	if pkt[22] != 0x44 {
		t.Fatalf("Read-SZL function should be 0x44, got 0x%02x", pkt[22])
	}
	if id := binary.BigEndian.Uint16(pkt[29:31]); id != 0x0011 {
		t.Fatalf("ssl id should be 0x0011, got 0x%04x", id)
	}
	if idx := binary.BigEndian.Uint16(pkt[31:33]); idx != 0x0000 {
		t.Fatalf("ssl index should be 0x0000, got 0x%04x", idx)
	}
}

func TestParseSZL0011_RealShape(t *testing.T) {
	// Build a SZL response that the parser must accept.
	// MLFB "6ES7515-2AM02-0AB0" + V2.9.4 firmware.
	mlfb := "6ES7515-2AM02-0AB0  "
	if len(mlfb) != 20 {
		t.Fatalf("MLFB length must be 20, got %d", len(mlfb))
	}
	rec := make([]byte, 28)
	binary.BigEndian.PutUint16(rec[0:2], 0x0001) // index = CPU
	copy(rec[2:22], mlfb)
	// BGType
	rec[22] = 0
	rec[23] = 0
	// Firmware V2.9 / .4
	rec[24] = 0x02
	rec[25] = 0x09
	rec[26] = 0x20
	rec[27] = 0x04

	resp := buildSZLResponse(t, 0x0011, [][]byte{rec})

	records, recLen, err := parseSZLResponse(resp)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if recLen != 28 || len(records) != 1 {
		t.Fatalf("want 1 record of 28 bytes, got %d records of %d", len(records), recLen)
	}

	info := &protocol.S7CommServerInfo{}
	mergeSZLRecords(info, 0x0011, records, recLen)

	if info.OrderCode == nil || *info.OrderCode != "6ES7515-2AM02-0AB0" {
		t.Fatalf("order code: %v", info.OrderCode)
	}
	if info.FirmwareVersion == nil || *info.FirmwareVersion != "V2.9.4" {
		t.Fatalf("firmware: %v", info.FirmwareVersion)
	}
}

func TestParseSZL001C_RealShape(t *testing.T) {
	mkRecord := func(index uint16, ascii string) []byte {
		rec := make([]byte, 34)
		binary.BigEndian.PutUint16(rec[0:2], index)
		copy(rec[2:34], []byte(ascii))
		return rec
	}
	records := [][]byte{
		mkRecord(1, "PLC_1"),
		mkRecord(2, "CPU 1515-2 PN"),
		mkRecord(4, "Original Siemens Equipment"),
		mkRecord(5, "S C-J5UR03612022"),
		mkRecord(6, "6ES7515-2AM02-0AB0"),
		mkRecord(7, "PLANT-OEM-1"),
	}

	resp := buildSZLResponse(t, 0x001C, records)

	parsed, recLen, err := parseSZLResponse(resp)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if recLen != 34 || len(parsed) != len(records) {
		t.Fatalf("want %d/34, got %d/%d", len(records), len(parsed), recLen)
	}

	info := &protocol.S7CommServerInfo{}
	mergeSZLRecords(info, 0x001C, parsed, recLen)

	checks := []struct {
		name string
		got  *string
		want string
	}{
		{"system_name", info.SystemName, "PLC_1"},
		{"module_name", info.ModuleName, "CPU 1515-2 PN"},
		{"copyright", info.Copyright, "Original Siemens Equipment"},
		{"serial", info.SerialNumber, "S C-J5UR03612022"},
		{"module_type", info.ModuleTypeName, "6ES7515-2AM02-0AB0"},
		{"plant_id", info.PlantId, "PLANT-OEM-1"},
	}
	for _, c := range checks {
		if c.got == nil || *c.got != c.want {
			t.Errorf("%s: got %v want %q", c.name, c.got, c.want)
		}
	}
}

func TestCPUFamilyFromOrderCode(t *testing.T) {
	cases := map[string]string{
		"6ES7515-2AM02-0AB0": "S7-1500",
		"6ES7214-1AG40-0XB0": "S7-1200",
		"6ES7315-2EH14-0AB0": "S7-300",
		"6ES7416-2XK04-0AB0": "S7-400",
		"6ES7155-6AU01-0CN0": "ET200",
		"6ED1052-1FB00-0BA8": "LOGO",
		"unknown":            "",
	}
	for code, want := range cases {
		if got := cpuFamilyFromOrderCode(code); got != want {
			t.Errorf("%s: got %q want %q", code, got, want)
		}
	}
}

func TestRackSlotFromTSAP(t *testing.T) {
	// S7-1500 called TSAP 03.00 → rack 0 slot 0
	r, s := rackSlotFromTSAP(tsapS7_1500.called)
	if r != 0 || s != 0 {
		t.Errorf("S7-1500 want (0,0) got (%d,%d)", r, s)
	}
	// S7-300 called TSAP 01.02 → rack 0 slot 2
	r, s = rackSlotFromTSAP(tsapS7_300.called)
	if r != 0 || s != 2 {
		t.Errorf("S7-300 want (0,2) got (%d,%d)", r, s)
	}
	// Synthetic rack=1, slot=3 → high 3 bits = 1 << 5 = 0x20 | 0x03 = 0x23
	r, s = rackSlotFromTSAP([2]byte{0x01, 0x23})
	if r != 1 || s != 3 {
		t.Errorf("synthetic want (1,3) got (%d,%d)", r, s)
	}
}

// buildSZLResponse synthesizes a User-Data response carrying the supplied SZL records.
// Layout (matching parseSZLResponse):
//
//	TPKT(4) + COTP DT(3) +
//	S7 header (12 bytes, ack-data userdata) +
//	S7 parameters (12 bytes) +
//	S7 data: ret(1) ts(1) datalen(2) szlhdr(8) records...
func buildSZLResponse(t *testing.T, sslID uint16, records [][]byte) []byte {
	t.Helper()
	if len(records) == 0 {
		t.Fatal("at least one record required")
	}
	recLen := len(records[0])
	for _, r := range records {
		if len(r) != recLen {
			t.Fatalf("record length mismatch: want %d got %d", recLen, len(r))
		}
	}
	dataLen := 12 + recLen*len(records) // ret+ts+datalen+szlhdr + records
	paramLen := 12
	headerSize := 12
	totalAfterCOTP := headerSize + paramLen + dataLen
	totalTPKT := 4 + 3 + totalAfterCOTP

	buf := make([]byte, 0, totalTPKT)
	// TPKT
	buf = append(buf, 0x03, 0x00, 0x00, 0x00)
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalTPKT))
	// COTP DT
	buf = append(buf, 0x02, 0xF0, 0x80)
	// S7 header (12 bytes): proto, rosctr, redundancy[2], pdu_ref[2],
	// param_len[2], data_len[2], err_class, err_code
	hdr := make([]byte, headerSize)
	hdr[0] = 0x32
	hdr[1] = 0x07
	binary.BigEndian.PutUint16(hdr[4:6], 0x0500) // pdu_ref
	binary.BigEndian.PutUint16(hdr[6:8], uint16(paramLen))
	binary.BigEndian.PutUint16(hdr[8:10], uint16(dataLen))
	buf = append(buf, hdr...)
	// S7 parameters (12 bytes for user data response)
	params := []byte{
		0x00, 0x01, 0x12, // header
		0x08,             // following length
		0x12,             // method 1 | type 2 (response)
		0x84,             // function group 8 + sub 4? actually we just need it to parse — params not strictly validated
		0x01,             // sequence
		0x00,             // data unit ref
		0x00,             // last data unit
		0x00, 0x00, 0x00, // error code + pad to reach paramLen
	}
	// Ensure we wrote exactly paramLen bytes.
	if len(params) < paramLen {
		params = append(params, make([]byte, paramLen-len(params))...)
	}
	params = params[:paramLen]
	buf = append(buf, params...)
	// S7 data block
	dataBlock := make([]byte, dataLen)
	dataBlock[0] = 0xFF // OK
	dataBlock[1] = 0x09 // octet string
	binary.BigEndian.PutUint16(dataBlock[2:4], uint16(dataLen-4))
	binary.BigEndian.PutUint16(dataBlock[4:6], sslID)
	binary.BigEndian.PutUint16(dataBlock[6:8], 0x0000)
	binary.BigEndian.PutUint16(dataBlock[8:10], uint16(recLen))
	binary.BigEndian.PutUint16(dataBlock[10:12], uint16(len(records)))
	off := 12
	for _, r := range records {
		copy(dataBlock[off:], r)
		off += recLen
	}
	buf = append(buf, dataBlock...)
	return buf
}

func TestParseSZLResponseRejectsTruncated(t *testing.T) {
	resp := []byte{0x03, 0x00, 0x00, 0x05, 0x02, 0xF0, 0x80}
	if _, _, err := parseSZLResponse(resp); err == nil {
		t.Fatal("expected error on truncated szl response")
	}
}
