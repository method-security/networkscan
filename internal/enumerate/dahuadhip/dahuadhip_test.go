package dahuadhip

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
)

// modernDahuaLoginResponseBody is a captured response from a Dahua DHIP
// firmware (2019+ era) replying to an empty-credential global.login probe.
// It was synthesised from the public reverse-engineering corpus around
// python-dahua-rpc and DahuaConsole — the 32-char-hex `realm` value mirrors
// the modern firmware era documented in SEC-702 TC-010 / TC-014.  No live
// device was probed to produce this fixture.
//
// Reference: https://github.com/mcw0/DahuaConsole
//
//nolint:lll
var modernDahuaLoginResponseBody = []byte(`{"id":1,"params":{"encryption":"Default","random":"1234567890ABCDEF","realm":"a1b2c3d4e5f60718293a4b5c6d7e8f90"},"error":{"code":268632064,"message":"failure"},"result":false,"session":2147483648}`)

// legacyDahuaLoginResponseBody is a synthesised fixture for the 2017-era
// firmware family (SEC-702 TC-008 — the OEM-rebranded HCVR cluster).  Legacy
// firmware leaks the plaintext device serial directly in the realm field.
//
//nolint:lll
var legacyDahuaLoginResponseBody = []byte(`{"id":1,"params":{"encryption":"OldDigest","realm":"3E023DBPAEMV65U"},"error":{"code":268632064,"message":"login failure"},"result":false,"session":0}`)

func TestBuildDhipFrame_HeaderLayout(t *testing.T) {
	body := []byte(`{"method":"global.login","params":{},"id":1,"session":0}`)
	frame := buildDhipFrame(body, 0)

	if len(frame) != dhipHeaderLen+len(body) {
		t.Fatalf("frame length: got %d, want %d", len(frame), dhipHeaderLen+len(body))
	}
	if !bytes.Equal(frame[0:8], dhipMagic) {
		t.Errorf("magic mismatch: got %x", frame[0:8])
	}
	if got := binary.LittleEndian.Uint64(frame[8:16]); got != 0 {
		t.Errorf("session id (initial probe should be 0): got %d", got)
	}
	if got := binary.LittleEndian.Uint32(frame[16:20]); int(got) != len(body) {
		t.Errorf("bodyLen mismatch: got %d, want %d", got, len(body))
	}
	if got := binary.LittleEndian.Uint32(frame[20:24]); int(got) != len(body) {
		t.Errorf("bodyLenDup mismatch: got %d, want %d", got, len(body))
	}
	for i := 24; i < dhipHeaderLen; i++ {
		if frame[i] != 0 {
			t.Errorf("reserved byte %d should be zero, got %x", i, frame[i])
		}
	}
	if !bytes.Equal(frame[dhipHeaderLen:], body) {
		t.Errorf("body payload mismatch")
	}
}

func TestParseDhipFrame_HappyPath(t *testing.T) {
	body := []byte("hello")
	frame := buildDhipFrame(body, 42)
	got, err := parseDhipFrame(frame)
	if err != nil {
		t.Fatalf("parseDhipFrame unexpected error: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("body slice mismatch: got %q, want %q", got, body)
	}
}

func TestValidateDhipHeader_HappyPath(t *testing.T) {
	body := []byte("hello")
	frame := buildDhipFrame(body, 42)
	bodyLen, err := validateDhipHeader(frame[:dhipHeaderLen])
	if err != nil {
		t.Fatalf("validateDhipHeader unexpected error: %v", err)
	}
	if int(bodyLen) != len(body) {
		t.Errorf("body length: got %d, want %d", bodyLen, len(body))
	}
}

func TestParseDhipFrame_RejectsBadMagic(t *testing.T) {
	bad := make([]byte, dhipHeaderLen)
	copy(bad[0:8], []byte{0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0})
	binary.LittleEndian.PutUint32(bad[16:20], 4)
	binary.LittleEndian.PutUint32(bad[20:24], 4)

	if _, err := parseDhipFrame(bad); err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestParseDhipFrame_RejectsLengthMismatch(t *testing.T) {
	hdr := make([]byte, dhipHeaderLen)
	copy(hdr[0:8], dhipMagic)
	binary.LittleEndian.PutUint32(hdr[16:20], 32)
	binary.LittleEndian.PutUint32(hdr[20:24], 64)

	if _, err := parseDhipFrame(hdr); err == nil {
		t.Fatal("expected error for length disagreement")
	}
}

func TestParseDhipFrame_RejectsOversizedBody(t *testing.T) {
	hdr := make([]byte, dhipHeaderLen)
	copy(hdr[0:8], dhipMagic)
	tooBig := uint32(dhipResponseBodyCap + 1)
	binary.LittleEndian.PutUint32(hdr[16:20], tooBig)
	binary.LittleEndian.PutUint32(hdr[20:24], tooBig)

	if _, err := parseDhipFrame(hdr); err == nil {
		t.Fatal("expected error for oversized body length")
	}
}

func TestParseDhipFrame_RejectsTruncated(t *testing.T) {
	if _, err := parseDhipFrame([]byte{0xa0, 0x05, 0x00}); err == nil {
		t.Fatal("expected truncation error")
	}
}

func TestParseLoginResponse_Modern(t *testing.T) {
	resp, err := parseLoginResponse(modernDahuaLoginResponseBody)
	if err != nil {
		t.Fatalf("parseLoginResponse error: %v", err)
	}
	if resp.ID == nil || *resp.ID != 1 {
		t.Errorf("id mismatch: got %v", resp.ID)
	}
	if resp.Params == nil || resp.Params.Encryption == nil || *resp.Params.Encryption != "Default" {
		t.Errorf("encryption mismatch: got %+v", resp.Params)
	}
	if resp.Params == nil || resp.Params.Realm == nil || *resp.Params.Realm != "a1b2c3d4e5f60718293a4b5c6d7e8f90" {
		t.Errorf("realm mismatch: got %+v", resp.Params)
	}
	if resp.Error == nil || resp.Error.Code == nil || *resp.Error.Code != 268632064 {
		t.Errorf("error code mismatch: got %+v", resp.Error)
	}
}

func TestParseLoginResponse_Legacy(t *testing.T) {
	resp, err := parseLoginResponse(legacyDahuaLoginResponseBody)
	if err != nil {
		t.Fatalf("parseLoginResponse error: %v", err)
	}
	if resp.Params == nil || resp.Params.Encryption == nil || *resp.Params.Encryption != "OldDigest" {
		t.Errorf("legacy encryption mismatch: got %+v", resp.Params)
	}
	if resp.Params == nil || resp.Params.Realm == nil || *resp.Params.Realm != "3E023DBPAEMV65U" {
		t.Errorf("legacy realm (plain serial) mismatch: got %+v", resp.Params)
	}
}

func TestRealmLooksLikePlainSerial(t *testing.T) {
	cases := []struct {
		realm string
		want  bool
	}{
		{"3E023DBPAEMV65U", true},                   // 15-char TC-008 plain serial
		{"DAHUA1234567", true},                      // 12-char (lower bound)
		{"ABCDE1234567890Z", true},                  // 16-char (upper bound)
		{"a1b2c3d4e5f60718293a4b5c6d7e8f90", false}, // 32-char modern hash (length > max)
		{"abcdef1234567", false},                    // lowercase rejected
		{"DAHUA-1234567", false},                    // hyphen rejected
		{"SHORT", false},                            // < min len
		{"", false},                                 // empty
	}
	for _, tc := range cases {
		if got := realmLooksLikePlainSerial(tc.realm); got != tc.want {
			t.Errorf("realmLooksLikePlainSerial(%q): got %v, want %v", tc.realm, got, tc.want)
		}
	}
}

func TestServerInfoFromResponse_ModernPopulatesAllFields(t *testing.T) {
	resp, err := parseLoginResponse(modernDahuaLoginResponseBody)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	si := serverInfoFromResponse(resp)

	if si.EncryptionMode == nil || *si.EncryptionMode != "Default" {
		t.Errorf("encryption: got %+v", si.EncryptionMode)
	}
	if si.AuthenticationRealm == nil || *si.AuthenticationRealm != "a1b2c3d4e5f60718293a4b5c6d7e8f90" {
		t.Errorf("realm: got %+v", si.AuthenticationRealm)
	}
	if si.RealmLooksLikePlainSerial == nil || *si.RealmLooksLikePlainSerial != false {
		t.Errorf("realm-looks-plain: modern firmware hash should be false, got %+v", si.RealmLooksLikePlainSerial)
	}
	if si.JsonRpcErrorCode == nil || *si.JsonRpcErrorCode != 268632064 {
		t.Errorf("error code: got %+v", si.JsonRpcErrorCode)
	}
}

func TestServerInfoFromResponse_LegacyFlagsPlainSerial(t *testing.T) {
	resp, err := parseLoginResponse(legacyDahuaLoginResponseBody)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	si := serverInfoFromResponse(resp)

	if si.RealmLooksLikePlainSerial == nil || *si.RealmLooksLikePlainSerial != true {
		t.Errorf("legacy plain-serial realm should set looksPlain=true, got %+v", si.RealmLooksLikePlainSerial)
	}
}

// TestEnumerateTarget_AgainstMockListener exercises EnumerateTarget end-to-end
// against an in-process TCP listener that speaks the DHIP wire framing.  The
// mock simply replays the modern legacy fixture; the test verifies the driver
// flips PortOpen + RequiresAuth and populates the parsed ServerInfo.
func TestEnumerateTarget_AgainstMockListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Drain the client's probe frame.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		// Send back a DHIP-framed modern response.
		resp := buildDhipFrame(modernDahuaLoginResponseBody, 0xDEADBEEFCAFEF00D)
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write(resp)
	}()

	lib := &LibraryEnumerateDahuaDhip{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, errs := lib.EnumerateTarget(ctx, ln.Addr().String())
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if out.EnumerateDahuaDhipDetails == nil {
		t.Fatal("nil details payload")
	}
	d := out.EnumerateDahuaDhipDetails
	if d.PortOpen == nil || !*d.PortOpen {
		t.Errorf("PortOpen should be true, got %+v", d.PortOpen)
	}
	if d.RequiresAuth == nil || !*d.RequiresAuth {
		t.Errorf("RequiresAuth should be true, got %+v", d.RequiresAuth)
	}
	if d.ServerInfo == nil {
		t.Fatal("ServerInfo should be populated")
	}
	if d.ServerInfo.EncryptionMode == nil || *d.ServerInfo.EncryptionMode != "Default" {
		t.Errorf("EncryptionMode: %+v", d.ServerInfo.EncryptionMode)
	}
	if d.RawResponse == nil || !strings.Contains(*d.RawResponse, "encryption") {
		t.Errorf("RawResponse not populated: %+v", d.RawResponse)
	}
	// Smoke-check that the union envelope still references our details.
	var _ enumeratefern.EnumerateServiceDetails = *out
}
