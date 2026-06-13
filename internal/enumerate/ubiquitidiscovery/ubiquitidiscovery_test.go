package ubiquitidiscovery

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// makeTLV builds a single TLV record (type + big-endian 16-bit length + value).
func makeTLV(t byte, value []byte) []byte {
	rec := make([]byte, 3+len(value))
	rec[0] = t
	binary.BigEndian.PutUint16(rec[1:3], uint16(len(value)))
	copy(rec[3:], value)
	return rec
}

// buildSyntheticDiscoveryResponse assembles a v1 Discovery response from the
// TLV records the caller hands it.  Used in unit tests to exercise the parser
// against known byte-for-byte inputs.
//
// The fixture data here is synthesised from the published Ubiquiti Discovery
// Protocol spec (https://help.ui.com/hc/en-us/articles/204976244) — no live
// device was probed to produce the fixture bytes.
func buildSyntheticDiscoveryResponse(version byte, records ...[]byte) []byte {
	var payload []byte
	for _, r := range records {
		payload = append(payload, r...)
	}
	out := make([]byte, 4+len(payload))
	out[0] = version
	out[1] = 0x00
	binary.BigEndian.PutUint16(out[2:4], uint16(len(payload)))
	copy(out[4:], payload)
	return out
}

func TestParseDiscoveryResponse_AirOSStyle(t *testing.T) {
	// Synthesised AirOS-style response with MAC+IP, hostname, firmware,
	// model, uptime — the typical AirOS 5.6 record set per SEC-702 TC-004.
	mac := []byte{0x00, 0x1A, 0xEF, 0x67, 0x31, 0x34}
	ip := []byte{109, 232, 0, 107}
	macIP := append(append([]byte{}, mac...), ip...)
	uptimeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(uptimeBytes, 86400) // 1 day

	pkt := buildSyntheticDiscoveryResponse(0x01,
		makeTLV(tlvTypeMacIPv1, macIP),
		makeTLV(tlvTypeHostname, []byte("NSM5\x00")),
		makeTLV(tlvTypeFirmwareLen, []byte("XW.v5.6.15-cb")),
		makeTLV(tlvTypeModel, []byte("NanoStation M5")),
		makeTLV(tlvTypeUptime, uptimeBytes),
		makeTLV(tlvTypePlatform, []byte("AirOS")),
	)

	version, records, err := parseDiscoveryResponse(pkt)
	if err != nil {
		t.Fatalf("parseDiscoveryResponse error: %v", err)
	}
	if version != 0x01 {
		t.Errorf("version: got %d, want 1", version)
	}
	if len(records) != 6 {
		t.Errorf("record count: got %d, want 6", len(records))
	}

	fp := extractFingerprint(records)
	if fp.MAC != "00:1a:ef:67:31:34" {
		t.Errorf("MAC: got %q", fp.MAC)
	}
	if fp.IPAddress != "109.232.0.107" {
		t.Errorf("IP: got %q", fp.IPAddress)
	}
	if fp.Hostname != "NSM5" {
		t.Errorf("hostname (trailing null should be trimmed): got %q", fp.Hostname)
	}
	if fp.Firmware != "XW.v5.6.15-cb" {
		t.Errorf("firmware: got %q", fp.Firmware)
	}
	if fp.Model != "NanoStation M5" {
		t.Errorf("model: got %q", fp.Model)
	}
	if fp.Platform != "AirOS" {
		t.Errorf("platform: got %q", fp.Platform)
	}
	if fp.UptimeSecs == nil || *fp.UptimeSecs != 86400 {
		t.Errorf("uptime: got %+v", fp.UptimeSecs)
	}
	if fp.RecordCount != 6 {
		t.Errorf("record count on fingerprint: got %d", fp.RecordCount)
	}
}

func TestParseDiscoveryResponse_TruncatedHeader(t *testing.T) {
	if _, _, err := parseDiscoveryResponse([]byte{0x01, 0x00}); err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestParseDiscoveryResponse_TLVValueTruncated(t *testing.T) {
	// Header claims 100-byte payload, only 5 bytes follow.
	pkt := []byte{0x01, 0x00, 0x00, 0x10, 0x01, 0x00, 0x40, 0x00, 0x00}
	_, _, err := parseDiscoveryResponse(pkt)
	if err == nil {
		t.Fatal("expected TLV-value-truncated error")
	}
}

func TestExtractFingerprint_UniFiStyle(t *testing.T) {
	// UniFi response signature: only MAC+IP + hostname + model + firmware,
	// no ESSID (wired AP).
	mac := []byte{0x80, 0x2A, 0xA8, 0x12, 0x34, 0x56}
	ip := []byte{10, 0, 0, 1}
	macIP := append(append([]byte{}, mac...), ip...)
	pkt := buildSyntheticDiscoveryResponse(0x02,
		makeTLV(tlvTypeMacIPv2, macIP),
		makeTLV(tlvTypeHostname, []byte("UAP-AC-PRO-1")),
		makeTLV(tlvTypeModel, []byte("UAP-AC-PRO")),
		makeTLV(tlvTypeFirmwareLen, []byte("6.6.65.15402")),
	)
	_, records, err := parseDiscoveryResponse(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fp := extractFingerprint(records)
	if fp.MAC != "80:2a:a8:12:34:56" {
		t.Errorf("MAC: got %q", fp.MAC)
	}
	if fp.IPAddress != "10.0.0.1" {
		t.Errorf("IP: got %q", fp.IPAddress)
	}
	if fp.Model != "UAP-AC-PRO" {
		t.Errorf("model: got %q", fp.Model)
	}
	if fp.Firmware != "6.6.65.15402" {
		t.Errorf("firmware: got %q", fp.Firmware)
	}
	if fp.Essid != "" {
		t.Errorf("essid should be empty for wired AP, got %q", fp.Essid)
	}
}

func TestTrimNonPrintable(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"hello\x00\x00", "hello"},
		{"trim me   ", "trim me"},
		{"\x01garbage", ""},
		{"", ""},
		{"ascii only", "ascii only"},
	}
	for _, tc := range cases {
		if got := trimNonPrintable(tc.in); got != tc.want {
			t.Errorf("trimNonPrintable(%q): got %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestEnumerateTarget_AgainstMockListener exercises the full driver against
// an in-process UDP listener that responds with the synthesised AirOS fixture.
func TestEnumerateTarget_AgainstMockListener(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = pc.Close() }()

	// Synthesised AirOS-style response.
	mac := []byte{0x00, 0x1A, 0xEF, 0x67, 0x31, 0x34}
	ip := []byte{109, 232, 0, 107}
	macIP := append(append([]byte{}, mac...), ip...)
	respPkt := buildSyntheticDiscoveryResponse(0x01,
		makeTLV(tlvTypeMacIPv1, macIP),
		makeTLV(tlvTypeFirmwareLen, []byte("XW.v5.6.15-cb")),
		makeTLV(tlvTypeModel, []byte("NanoStation M5")),
	)

	go func() {
		buf := make([]byte, 1024)
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_ = pc.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = pc.WriteTo(respPkt, addr)
	}()

	lib := &LibraryEnumerateUbiquitiDiscovery{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, errs := lib.EnumerateTarget(ctx, pc.LocalAddr().String())
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	d := out.EnumerateUbiquitiDiscoveryDetails
	if d.PortOpen == nil || !*d.PortOpen {
		t.Errorf("PortOpen should be true, got %+v", d.PortOpen)
	}
	if d.ServerInfo == nil {
		t.Fatal("ServerInfo should be populated")
	}
	if d.ServerInfo.MacAddress == nil || *d.ServerInfo.MacAddress != "00:1A:EF:67:31:34" {
		t.Errorf("MAC: got %+v", d.ServerInfo.MacAddress)
	}
	if d.ServerInfo.DeviceModel == nil || *d.ServerInfo.DeviceModel != "NanoStation M5" {
		t.Errorf("model: got %+v", d.ServerInfo.DeviceModel)
	}
	if d.ServerInfo.FirmwareVersion == nil || *d.ServerInfo.FirmwareVersion != "XW.v5.6.15-cb" {
		t.Errorf("firmware: got %+v", d.ServerInfo.FirmwareVersion)
	}
}
