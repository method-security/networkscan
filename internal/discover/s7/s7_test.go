package s7

import (
	"context"
	"net"
	"strings"
	"testing"

	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

func TestParseHostPort_BareHostDefaults102(t *testing.T) {
	h, p, err := parseHostPort("192.0.2.1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if h != "192.0.2.1" || p != 102 {
		t.Fatalf("got %s:%d", h, p)
	}
}

func TestParseHostPort_HostWithPort(t *testing.T) {
	h, p, err := parseHostPort("plc.example:102")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if h != "plc.example" || p != 102 {
		t.Fatalf("got %s:%d", h, p)
	}
}

func TestParseHostPort_BracketedIPv6(t *testing.T) {
	h, p, err := parseHostPort("[2001:db8::1]:102")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if h != "2001:db8::1" || p != 102 {
		t.Fatalf("got %s:%d", h, p)
	}
}

func TestParseHostPort_UnbracketedIPv6Rejected(t *testing.T) {
	if _, _, err := parseHostPort("2001:db8::1"); err == nil {
		t.Fatal("want error on unbracketed IPv6")
	}
}

func TestParseHostPort_BadPort(t *testing.T) {
	if _, _, err := parseHostPort("host:notaport"); err == nil {
		t.Fatal("expected error on non-numeric port")
	}
	if _, _, err := parseHostPort("host:0"); err == nil {
		t.Fatal("expected error on port 0")
	}
}

func TestRunDiscoverS7_NoTargets(t *testing.T) {
	report, err := RunDiscoverS7(context.Background(), discoverfern.DiscoverS7Config{Targets: nil, Timeout: 1})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(report.Errors) == 0 {
		t.Fatal("expected an error about empty targets")
	}
	if !strings.Contains(strings.Join(report.Errors, " "), "no targets") {
		t.Fatalf("unexpected error %v", report.Errors)
	}
}

func TestRunDiscoverS7_UnreachableHostRecordedAsError(t *testing.T) {
	// 127.0.0.0/8 reserved; should hit ECONNREFUSED or timeout quickly.
	cfg := discoverfern.DiscoverS7Config{
		Targets: []string{"127.0.0.1:1"},
		Timeout: 1,
	}
	report, err := RunDiscoverS7(context.Background(), cfg)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if report.Result == nil || len(report.Result.Details) != 0 {
		t.Fatalf("expected zero details, got %+v", report.Result)
	}
	if len(report.Errors) == 0 {
		t.Fatal("expected per-target error")
	}
}

// Verify the in-band probe against a goroutine pretending to be a PLC.
func TestProbe_AgainstFakePLC(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// 1. Read COTP CR.
		buf := make([]byte, 256)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		// Reply with COTP CC.
		cc := []byte{0x03, 0x00, 0x00, 0x16, 0x11, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x02, 0x00, 0xC2, 0x02, 0x03, 0x00}
		if _, err := conn.Write(cc); err != nil {
			return
		}

		// 2. Read S7 SETUP.
		if _, err := conn.Read(buf); err != nil {
			return
		}
		// Reply with S7 SETUP ack-data: TPKT(4)+COTP(3)+header(12), all zero error.
		ack := make([]byte, 19)
		ack[0] = 0x03
		ack[1] = 0x00
		ack[2] = 0x00
		ack[3] = 0x13
		ack[4] = 0x02
		ack[5] = 0xF0
		ack[6] = 0x80
		ack[7] = 0x32
		ack[8] = 0x03
		if _, err := conn.Write(ack); err != nil {
			return
		}

		// 3. Read SZL 0x0011.
		if _, err := conn.Read(buf); err != nil {
			return
		}
		// Reply with a one-record SZL 0x0011 — MLFB + V2.9.4.
		szlOO11 := mockSZLResponse(0x0011, [][]byte{mockMlfbRecord("6ES7515-2AM02-0AB0  ", 0x02, 0x09, 0x04)})
		if _, err := conn.Write(szlOO11); err != nil {
			return
		}

		// 4. Read SZL 0x001C.
		if _, err := conn.Read(buf); err != nil {
			return
		}
		szl001C := mockSZLResponse(0x001C, [][]byte{
			mockAsciiRecord(2, "CPU 1515-2 PN"),
			mockAsciiRecord(5, "S C-J5UR03612022"),
		})
		_, _ = conn.Write(szl001C)
	}()

	host, portStr, _ := net.SplitHostPort(listener.Addr().String())
	ip := net.ParseIP(host)
	port := mustAtoi(t, portStr)

	info, stepErrors, err := Probe(context.Background(), ip, port, Options{Timeout: 2, TSAPVariant: TSAPVariantS7_1500})
	if err != nil {
		t.Fatalf("probe: %v (steps=%v)", err, stepErrors)
	}
	if info == nil {
		t.Fatal("nil info")
	}
	if info.OrderCode == nil || *info.OrderCode != "6ES7515-2AM02-0AB0" {
		t.Fatalf("order code: %v", info.OrderCode)
	}
	if info.FirmwareVersion == nil || *info.FirmwareVersion != "V2.9.4" {
		t.Fatalf("firmware: %v", info.FirmwareVersion)
	}
	if info.ModuleName == nil || *info.ModuleName != "CPU 1515-2 PN" {
		t.Fatalf("module name: %v", info.ModuleName)
	}
	if info.CpuType == nil || *info.CpuType != "CPU 1515-2 PN" {
		t.Fatalf("cpu type: %v", info.CpuType)
	}
	if info.SerialNumber == nil || *info.SerialNumber != "S C-J5UR03612022" {
		t.Fatalf("serial: %v", info.SerialNumber)
	}
	if info.CpuFamily == nil || *info.CpuFamily != "S7-1500" {
		t.Fatalf("cpu family: %v", info.CpuFamily)
	}
	if info.Rack == nil || *info.Rack != 0 || info.Slot == nil || *info.Slot != 0 {
		t.Fatalf("rack/slot: r=%v s=%v", info.Rack, info.Slot)
	}
}

// mockMlfbRecord builds a 28-byte SZL 0x0011 record with index=1 and the
// supplied MLFB + firmware bytes.
func mockMlfbRecord(mlfb string, v, r, a byte) []byte {
	rec := make([]byte, 28)
	rec[0] = 0x00
	rec[1] = 0x01
	copy(rec[2:22], mlfb)
	// BGType zero
	rec[24] = v
	rec[25] = r
	rec[26] = 0x20
	rec[27] = a
	return rec
}

func mockAsciiRecord(index uint16, ascii string) []byte {
	rec := make([]byte, 34)
	rec[0] = byte(index >> 8)
	rec[1] = byte(index)
	copy(rec[2:34], []byte(ascii))
	return rec
}

func mockSZLResponse(sslID uint16, records [][]byte) []byte {
	if len(records) == 0 {
		return nil
	}
	recLen := len(records[0])
	dataLen := 12 + recLen*len(records)
	paramLen := 12
	totalTPKT := 4 + 3 + 12 + paramLen + dataLen

	buf := make([]byte, totalTPKT)
	buf[0] = 0x03
	buf[1] = 0x00
	buf[2] = byte(totalTPKT >> 8)
	buf[3] = byte(totalTPKT & 0xFF)
	buf[4] = 0x02
	buf[5] = 0xF0
	buf[6] = 0x80
	// S7 header (12 bytes at offset 7..18). param_len at resp[13:15],
	// data_len at resp[15:17].
	buf[7] = 0x32
	buf[8] = 0x07
	buf[13] = byte(paramLen >> 8)
	buf[14] = byte(paramLen & 0xFF)
	buf[15] = byte(dataLen >> 8)
	buf[16] = byte(dataLen & 0xFF)
	// error_class / error_code at resp[17] / resp[18] left zero (success).
	// params (offsets 19..30 are paramStart..paramStart+paramLen-1)
	off := 19
	buf[off+0] = 0x00
	buf[off+1] = 0x01
	buf[off+2] = 0x12
	buf[off+3] = 0x08
	buf[off+4] = 0x12
	buf[off+5] = 0x84
	buf[off+6] = 0x01
	buf[off+7] = 0x00
	buf[off+8] = 0x00
	buf[off+9] = 0x00
	buf[off+10] = 0x00
	buf[off+11] = 0x00
	// data starts at off+12
	off += 12
	buf[off+0] = 0xFF
	buf[off+1] = 0x09
	buf[off+2] = byte((dataLen - 4) >> 8)
	buf[off+3] = byte((dataLen - 4) & 0xFF)
	buf[off+4] = byte(sslID >> 8)
	buf[off+5] = byte(sslID & 0xFF)
	buf[off+6] = 0x00
	buf[off+7] = 0x00
	buf[off+8] = byte(recLen >> 8)
	buf[off+9] = byte(recLen & 0xFF)
	buf[off+10] = byte(len(records) >> 8)
	buf[off+11] = byte(len(records) & 0xFF)
	off += 12
	for _, r := range records {
		copy(buf[off:], r)
		off += recLen
	}
	return buf
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("bad numeric %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}
