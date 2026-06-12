package ipmi

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestBuildRAKPMessage1Layout(t *testing.T) {
	var nonce [RAKPNonceSize]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	req, err := BuildRAKPMessage1(0xAA, 0xDEADBEEF, nonce, "admin")
	if err != nil {
		t.Fatalf("BuildRAKPMessage1 err = %v", err)
	}
	// envelope + 12-byte session hdr + 28 (fixed) + 5 (username) payload.
	want := RMCPHeaderSize + IPMI20SessionHeaderSize + 28 + 5
	if len(req) != want {
		t.Fatalf("len(req) = %d, want %d", len(req), want)
	}
	if req[5] != PayloadTypeRAKPMessage1 {
		t.Fatalf("payload type = 0x%02x, want 0x12", req[5])
	}
	payload := req[RMCPHeaderSize+IPMI20SessionHeaderSize:]
	if payload[0] != 0xAA {
		t.Fatalf("message tag = 0x%02x, want 0xAA", payload[0])
	}
	if got := binary.LittleEndian.Uint32(payload[4:8]); got != 0xDEADBEEF {
		t.Fatalf("bmc session id = 0x%08x, want 0xDEADBEEF", got)
	}
	for i := 0; i < RAKPNonceSize; i++ {
		if payload[8+i] != nonce[i] {
			t.Fatalf("nonce byte %d = 0x%02x, want 0x%02x", i, payload[8+i], nonce[i])
		}
	}
	if payload[24] != rakp1NameLookupAdmin {
		t.Fatalf("role byte = 0x%02x, want 0x14", payload[24])
	}
	if payload[27] != byte(len("admin")) {
		t.Fatalf("username length = %d, want %d", payload[27], len("admin"))
	}
	if string(payload[28:33]) != "admin" {
		t.Fatalf("username = %q, want admin", payload[28:33])
	}
}

func TestBuildRAKPMessage1RejectsLongUsername(t *testing.T) {
	var nonce [RAKPNonceSize]byte
	long := strings.Repeat("a", MaxUsernameLength+1)
	if _, err := BuildRAKPMessage1(0, 0, nonce, long); err == nil {
		t.Fatalf("expected error on overlong username")
	}
}

// buildRAKP2 synthesizes a successful RAKP-2 wire response. The
// key-exchange-authcode is set to fixed bytes the test asserts on.
func buildRAKP2(t *testing.T, status byte) []byte {
	t.Helper()
	payload := make([]byte, 40+HMACSHA1AuthCodeSize)
	payload[0] = 0xAA
	payload[1] = status
	binary.LittleEndian.PutUint32(payload[4:8], 0xA1A2A3A4)
	// BMC nonce 0x10..0x1F.
	for i := 0; i < RAKPNonceSize; i++ {
		payload[8+i] = byte(0x10 + i)
	}
	// BMC GUID 0x20..0x2F.
	for i := 0; i < 16; i++ {
		payload[24+i] = byte(0x20 + i)
	}
	// HMAC bytes 0xAA..0xBD.
	for i := 0; i < HMACSHA1AuthCodeSize; i++ {
		payload[40+i] = byte(0xAA + i)
	}
	rmcp := BuildRMCPHeader()
	sess := BuildIPMI20SessionHeader(PayloadTypeRAKPMessage2, 0, 0, uint16(len(payload)))
	return append(append(append([]byte{}, rmcp...), sess...), payload...)
}

func TestParseRAKPMessage2Success(t *testing.T) {
	resp := buildRAKP2(t, RMCPPlusStatusNoErrors)
	m, err := ParseRAKPMessage2(resp)
	if err != nil {
		t.Fatalf("ParseRAKPMessage2 err = %v", err)
	}
	if !m.Success() {
		t.Fatalf("expected Success()=true")
	}
	if len(m.KeyExchangeAuthCode) != HMACSHA1AuthCodeSize {
		t.Fatalf("KEC length = %d, want %d", len(m.KeyExchangeAuthCode), HMACSHA1AuthCodeSize)
	}
	if m.KeyExchangeAuthCode[0] != 0xAA || m.KeyExchangeAuthCode[19] != 0xAA+19 {
		t.Fatalf("KEC bytes wrong: %v", m.KeyExchangeAuthCode)
	}
	if m.BMCGUID[0] != 0x20 || m.BMCGUID[15] != 0x2F {
		t.Fatalf("BMC GUID wrong")
	}
}

// TestParseRAKPMessage2TruncatedHMAC asserts that a RAKP-2 reply with
// status==0 but fewer than 60 bytes of payload (40 fixed + 20 HMAC-SHA1)
// is rejected rather than propagated as a "valid" disclosure with a
// short auth code. Without this guard the hashcat -m 7300 line we emit
// would be unusable and the existence-oracle field would lie.
func TestParseRAKPMessage2TruncatedHMAC(t *testing.T) {
	resp := buildRAKP2(t, RMCPPlusStatusNoErrors)
	// Trim the HMAC from 20 bytes down to 4. Payload length must be
	// updated in the session header so ParseIPMI20Payload doesn't
	// error first.
	const payloadStart = RMCPHeaderSize + IPMI20SessionHeaderSize
	const newPayloadLen = 44
	binary.LittleEndian.PutUint16(resp[RMCPHeaderSize+10:RMCPHeaderSize+12], newPayloadLen)
	resp = resp[:payloadStart+newPayloadLen]
	_, err := ParseRAKPMessage2(resp)
	if err == nil {
		t.Fatalf("expected error on RAKP-2 with truncated HMAC, got nil")
	}
}

func TestParseRAKPMessage2UnauthorizedName(t *testing.T) {
	resp := buildRAKP2(t, RMCPPlusStatusUnauthorizedName)
	// The error reply ends at the SID echo (8 bytes payload), per
	// real BMC behavior. Truncate accordingly.
	const payloadStart = RMCPHeaderSize + IPMI20SessionHeaderSize
	// Rewrite payload-length to 8.
	binary.LittleEndian.PutUint16(resp[RMCPHeaderSize+10:RMCPHeaderSize+12], 8)
	resp = resp[:payloadStart+8]
	m, err := ParseRAKPMessage2(resp)
	if err != nil {
		t.Fatalf("ParseRAKPMessage2 err = %v", err)
	}
	if m.Success() {
		t.Fatalf("expected Success()=false on unauthorized name")
	}
}

// TestFormatHashcatLineRoundTrip computes HMAC-SHA1 over the same
// salt our formatter emits and asserts the formatter's hex output
// matches. This guards against silent salt-layout drift; if hashcat
// ever rejects the line we ship, it's not because we re-ordered the
// salt fields.
func TestFormatHashcatLineRoundTrip(t *testing.T) {
	password := "PASSW0RD"
	username := "admin"
	consoleNonce := make([]byte, 16)
	bmcNonce := make([]byte, 16)
	bmcGUID := make([]byte, 16)
	for i := 0; i < 16; i++ {
		consoleNonce[i] = byte(i)
		bmcNonce[i] = byte(0x40 + i)
		bmcGUID[i] = byte(0x80 + i)
	}
	const bmcSID uint32 = 0x11112222
	const consoleSID uint32 = 0x33334444
	role := HashcatRoleByte

	mac := hmac.New(sha1.New, []byte(password))
	var sidBuf [4]byte
	binary.LittleEndian.PutUint32(sidBuf[:], bmcSID)
	mac.Write(sidBuf[:])
	binary.LittleEndian.PutUint32(sidBuf[:], consoleSID)
	mac.Write(sidBuf[:])
	mac.Write(consoleNonce)
	mac.Write(bmcNonce)
	mac.Write(bmcGUID)
	mac.Write([]byte{role, byte(len(username))})
	mac.Write([]byte(username))
	expectedHMAC := mac.Sum(nil)

	line := FormatHashcatLine(username, bmcSID, consoleSID, consoleNonce, bmcNonce, bmcGUID, role, expectedHMAC)
	parts := strings.Split(line, ":")
	if len(parts) != 3 {
		t.Fatalf("hashcat line should have 3 colon-separated fields; got %d: %q", len(parts), line)
	}
	if parts[0] != username {
		t.Fatalf("username field = %q, want %q", parts[0], username)
	}
	if parts[2] != hex.EncodeToString(expectedHMAC) {
		t.Fatalf("hmac field = %q, want %q", parts[2], hex.EncodeToString(expectedHMAC))
	}
	// Salt must contain all field bytes in spec order.
	saltBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("salt is not hex: %v", err)
	}
	wantSize := 4 + 4 + len(consoleNonce) + len(bmcNonce) + len(bmcGUID) + 1 + 1 + len(username)
	if len(saltBytes) != wantSize {
		t.Fatalf("salt len = %d, want %d", len(saltBytes), wantSize)
	}
	// Re-HMAC the decoded salt — must reproduce the same digest.
	mac2 := hmac.New(sha1.New, []byte(password))
	mac2.Write(saltBytes)
	if !hmac.Equal(mac2.Sum(nil), expectedHMAC) {
		t.Fatalf("hashcat salt does not round-trip through HMAC-SHA1")
	}
}
