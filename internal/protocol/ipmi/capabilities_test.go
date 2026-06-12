package ipmi

import (
	"errors"
	"testing"
)

// authCapsResponse builds a synthetic Get-Channel-Authentication-
// Capabilities response with the supplied auth-type-support bytes.
// The IPMB framing portion is filled in with the standard reply
// addressing so the parser doesn't reject it.
func authCapsResponse(t *testing.T, bitmap1, bitmap2, bitmap3 byte, oemLSB, oemMid, oemMSB, oemAux byte, truncate int) []byte {
	t.Helper()
	resp := []byte{
		// RMCP header.
		0x06, 0x00, 0xFF, 0x07,
		// IPMI v1.5 unauthenticated session header.
		0x00,                   // auth type (session header — always 0x00 on unauth)
		0x00, 0x00, 0x00, 0x00, // session seq
		0x00, 0x00, 0x00, 0x00, // session id
		0x10, // msg len
		// IPMB response (offsets 14-19).
		0x81, // rqAddr
		0x1C, // netfn/lun (response of App, lun=0)
		IPMBChecksum([]byte{0x81, 0x1C}),
		0x20, // rsAddr
		0x00, // rsSeq | lun
		0x38, // cmd echo
		// Response data (offsets 20-28).
		0x00, // completion code
		0x01, // channel #
		bitmap1, bitmap2, bitmap3,
		oemLSB, oemMid, oemMSB, oemAux,
		// chk2 — not validated by the parser, fill with 0.
		0x00,
	}
	if truncate > 0 && truncate < len(resp) {
		resp = resp[:truncate]
	}
	return resp
}

func TestParseAuthCapabilitiesFullIPMI20(t *testing.T) {
	// Bitmap1 = 0x97: None (bit 0) + MD2 (1) + MD5 (2) + Straight (4) + IPMI 2.0 ext (7).
	// Bitmap2 = 0x05: anon enabled (bit 0) + non-null usernames (bit 2).
	// Bitmap3 = 0x03: v1.5 + v2.0 supported.
	resp := authCapsResponse(t, 0x97, 0x05, 0x03, 0x10, 0x20, 0x30, 0x00, 0)
	caps, err := ParseAuthCapabilities(resp)
	if err != nil {
		t.Fatalf("ParseAuthCapabilities() err = %v", err)
	}
	if !caps.Bitmap1Parsed || !caps.Bitmap2Parsed || !caps.Bitmap3Parsed || !caps.OEMIDParsed {
		t.Fatalf("expected all Bitmap*Parsed=true on full IPMI 2.0 reply, got %+v", caps)
	}
	if !caps.AuthNone || !caps.AuthMD2 || !caps.AuthMD5 || !caps.AuthStraight {
		t.Fatalf("auth bitmap1 mis-parsed: %+v", caps)
	}
	if caps.AuthOEM {
		t.Fatalf("expected AuthOEM=false, got true")
	}
	if !caps.IPMI20ExtendedCapabilities {
		t.Fatalf("expected IPMI20ExtendedCapabilities=true")
	}
	if !caps.AnonymousLoginEnabled || !caps.NonNullUsernameEnabled {
		t.Fatalf("auth bitmap2 mis-parsed: %+v", caps)
	}
	if caps.NullUsernameEnabled {
		t.Fatalf("expected NullUsernameEnabled=false")
	}
	if !caps.IPMI15Supported || !caps.IPMI20Supported {
		t.Fatalf("auth bitmap3 mis-parsed: %+v", caps)
	}
	if got, want := caps.Version(), "2.0"; got != want {
		t.Fatalf("Version() = %q, want %q", got, want)
	}
	if got, want := caps.OEMID, uint32(0x302010); got != want {
		t.Fatalf("OEMID = 0x%x, want 0x%x", got, want)
	}
	if caps.ChannelNumber != 0x01 {
		t.Fatalf("ChannelNumber = 0x%02x, want 0x01", caps.ChannelNumber)
	}
}

// TestParseAuthCapabilitiesRegressionByteOffset asserts the bug fix
// the ticket calls out — the old plugin read offset 4 (session header
// auth_type, always 0x00) and reported that as the "auth type" string.
// We now read offset 22 (Auth-Type-Support-1), the real bitmap byte.
func TestParseAuthCapabilitiesRegressionByteOffset(t *testing.T) {
	// Bitmap1 = 0x15 — None + MD5 + Straight. Old code returned
	// "0x00"; new parser must read this byte.
	resp := authCapsResponse(t, 0x15, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0)
	caps, err := ParseAuthCapabilities(resp)
	if err != nil {
		t.Fatalf("ParseAuthCapabilities() err = %v", err)
	}
	if !caps.AuthNone || !caps.AuthMD5 || !caps.AuthStraight {
		t.Fatalf("expected None+MD5+Straight, got %+v", caps)
	}
	if caps.AuthMD2 {
		t.Fatalf("expected AuthMD2=false")
	}
	if !caps.IPMI20Supported {
		t.Fatalf("expected IPMI20Supported=true (bitmap3 bit 1)")
	}
	raw, ok := CopyAuthTypeSupport1(resp)
	if !ok || raw != 0x15 {
		t.Fatalf("CopyAuthTypeSupport1 = (0x%02x, %v), want (0x15, true)", raw, ok)
	}
}

func TestParseAuthCapabilitiesIPMI15Only(t *testing.T) {
	// Truncate the response after Auth-Type-Support-1 — a v1.5-only
	// BMC may legitimately stop there. The parser must still succeed
	// with a partial struct (no IPMI 2.0 fields) and report
	// Bitmap2Parsed=Bitmap3Parsed=OEMIDParsed=false so the plugin
	// knows to omit those Fern fields instead of lying about them.
	const truncateAfter = RMCPHeaderSize + IPMI15SessionHeaderSize + 9 // through bitmap1
	resp := authCapsResponse(t, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, truncateAfter)
	caps, err := ParseAuthCapabilities(resp)
	if err != nil {
		t.Fatalf("ParseAuthCapabilities() err = %v", err)
	}
	if !caps.AuthMD2 || !caps.AuthMD5 || !caps.AuthStraight {
		t.Fatalf("bitmap1 mis-parsed: %+v", caps)
	}
	if !caps.Bitmap1Parsed {
		t.Fatalf("expected Bitmap1Parsed=true on bitmap1-present reply")
	}
	if caps.Bitmap2Parsed || caps.Bitmap3Parsed || caps.OEMIDParsed {
		t.Fatalf("expected Bitmap2/3/OEMIDParsed=false on truncated reply, got %+v", caps)
	}
	if caps.IPMI15Supported || caps.IPMI20Supported {
		t.Fatalf("expected IPMI15/20Supported=false on truncated reply, got %+v", caps)
	}
	if got, want := caps.Version(), "1.5"; got != want {
		t.Fatalf("Version() = %q, want %q", got, want)
	}
}

// TestParseAuthCapabilitiesBitmap1BoundsRegression locks down the
// CVE-class bounds bug bugbot caught on the first PR push: with the
// old `len(resp) < ipmbStart+8` check, a 22-byte response passed the
// guard, then `resp[ipmbStart+8] = resp[22]` panicked (valid indices
// are 0..21). The fix raises the guard to `< ipmbStart+9` and this
// test asserts a 22-byte response now errors cleanly instead of
// crashing the discovery worker.
func TestParseAuthCapabilitiesBitmap1BoundsRegression(t *testing.T) {
	resp := authCapsResponse(t, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0)
	// Truncate to exactly RMCPHeader (4) + sessionHeader (10) +
	// IPMB-fixed-bytes (8) = 22 bytes — through the channel-number
	// data byte but missing bitmap1 at offset 22.
	resp = resp[:RMCPHeaderSize+IPMI15SessionHeaderSize+8]
	if _, err := ParseAuthCapabilities(resp); err == nil {
		t.Fatalf("expected truncation error on 22-byte response (would have panicked under the old check)")
	}
}

func TestParseAuthCapabilitiesShortRMCP(t *testing.T) {
	_, err := ParseAuthCapabilities([]byte{0x06, 0x00})
	if err == nil {
		t.Fatalf("expected error on short RMCP header")
	}
}

func TestParseAuthCapabilitiesTruncatedBeforeChannelByte(t *testing.T) {
	resp := authCapsResponse(t, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, RMCPHeaderSize+IPMI15SessionHeaderSize+4)
	_, err := ParseAuthCapabilities(resp)
	if err == nil {
		t.Fatalf("expected truncation error")
	}
	if !errors.Is(err, ErrTruncatedResponse) {
		t.Fatalf("err = %v, want ErrTruncatedResponse wrap", err)
	}
}

func TestParseAuthCapabilitiesCompletionCodeNonZero(t *testing.T) {
	resp := authCapsResponse(t, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0)
	// Overwrite the completion-code byte at offset RMCPHeader+SessionHeader+6
	// = 4+10+6 = 20.
	resp[RMCPHeaderSize+IPMI15SessionHeaderSize+6] = 0xCC
	_, err := ParseAuthCapabilities(resp)
	if err == nil {
		t.Fatalf("expected error on BMC completion-code non-zero")
	}
}

func TestSupportsCipherZero(t *testing.T) {
	if (AuthCapabilities{AuthNone: true}).SupportsCipherZero() != true {
		t.Fatalf("AuthNone=true should report SupportsCipherZero=true")
	}
	if (AuthCapabilities{}).SupportsCipherZero() != false {
		t.Fatalf("AuthNone=false should report SupportsCipherZero=false")
	}
}
