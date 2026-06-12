package ipmi

import (
	"fmt"
)

// Get-Channel-Auth-Caps IPMB framing constants. These mirror the
// IPMI 2.0 spec section 22.13 and replace the hand-rolled magic bytes
// the old discover plugin carried inline.
const (
	// IPMB request framing.
	getChannelAuthCapsRsAddr       byte = 0x20 // responder address (BMC's slave addr)
	getChannelAuthCapsReqNetFnLUN  byte = 0x18 // NetFn=App(6)<<2, LUN=0
	getChannelAuthCapsRqAddr       byte = 0x81 // requester address (any non-BMC)
	getChannelAuthCapsReqSeqLUN    byte = 0x00 // RqSeq=0<<2, LUN=0
	getChannelAuthCapsCommand      byte = 0x38 // Get Channel Auth Capabilities command
	getChannelAuthCapsChannelByte  byte = 0x8E // ch=0xE (current) | bit7=request IPMI 2.0 caps
	getChannelAuthCapsPrivilegeAdm byte = 0x04 // requested privilege = Administrator
)

// BuildGetChannelAuthCapabilitiesRequest constructs the IPMI v1.5
// "Get Channel Authentication Capabilities" message used as the
// always-run discovery probe. The channel field has bit 7 set so the
// BMC returns IPMI 2.0 extended capabilities (the bytes Auth-Type-
// Support-2/3 we need to detect RMCP+ support).
func BuildGetChannelAuthCapabilitiesRequest() []byte {
	// Build the IPMB message portion first so we can compute checksums
	// over the right ranges.
	header1 := []byte{getChannelAuthCapsRsAddr, getChannelAuthCapsReqNetFnLUN}
	check1 := IPMBChecksum(header1)
	body := []byte{
		getChannelAuthCapsRqAddr,
		getChannelAuthCapsReqSeqLUN,
		getChannelAuthCapsCommand,
		getChannelAuthCapsChannelByte,
		getChannelAuthCapsPrivilegeAdm,
	}
	check2 := IPMBChecksum(body)

	ipmbMsg := make([]byte, 0, len(header1)+1+len(body)+1)
	ipmbMsg = append(ipmbMsg, header1...)
	ipmbMsg = append(ipmbMsg, check1)
	ipmbMsg = append(ipmbMsg, body...)
	ipmbMsg = append(ipmbMsg, check2)

	rmcp := BuildRMCPHeader()
	sess := BuildIPMI15SessionHeader(byte(len(ipmbMsg)))

	out := make([]byte, 0, len(rmcp)+len(sess)+len(ipmbMsg))
	out = append(out, rmcp...)
	out = append(out, sess...)
	out = append(out, ipmbMsg...)
	return out
}

// AuthCapabilities is the parsed Get-Channel-Auth-Capabilities
// response. The Bitmap*Parsed booleans report whether the source byte
// for each group of fields was actually present in the response: a
// v1.5-only BMC may legitimately truncate after Auth-Type-Support-1
// and the caller must distinguish "field is false" from "we never read
// the byte." Bitmap1 is always parsed on a successful return.
type AuthCapabilities struct {
	// Channel number echoed by the BMC (response data byte 1).
	ChannelNumber byte

	// Auth-Type-Support-1 (response data byte 2):
	//   bit 0 None / 1 MD2 / 2 MD5 / 4 Straight password / 5 OEM
	//   bit 7 = IPMI 2.0 extended caps available
	AuthNone, AuthMD2, AuthMD5, AuthStraight, AuthOEM bool
	IPMI20ExtendedCapabilities                        bool

	// Auth-Type-Support-2 (response data byte 3) — user-class flags.
	KgSet                  bool
	PerMessageAuthDisabled bool
	UserLevelAuthDisabled  bool
	NonNullUsernameEnabled bool
	NullUsernameEnabled    bool
	AnonymousLoginEnabled  bool

	// Auth-Type-Support-3 (response data byte 4, IPMI 2.0 only) —
	// supported session-level protocols.
	IPMI15Supported bool
	IPMI20Supported bool

	// OEM identifier (response data bytes 5-7, LSB-first 24-bit).
	OEMID uint32

	// Tracking which optional bitmaps actually appeared in the response.
	// Bitmap1Parsed is always true on a successful return; Bitmap2Parsed
	// covers Auth-Type-Support-2 (Anonymous/Null/etc + per-msg flags);
	// Bitmap3Parsed covers Auth-Type-Support-3 (IPMI 1.5/2.0 support);
	// OEMIDParsed covers the OEM ID bytes 5-7.
	Bitmap1Parsed bool
	Bitmap2Parsed bool
	Bitmap3Parsed bool
	OEMIDParsed   bool
}

// Version returns "2.0" if the bitmap reports IPMI 2.0 support and
// "1.5" otherwise. This replaces the hand-rolled (and broken)
// `response[19] & 0x02` check the old plugin used.
func (c AuthCapabilities) Version() string {
	if c.IPMI20Supported {
		return "2.0"
	}
	return "1.5"
}

// SupportsCipherZero returns true if the BMC advertises the "None"
// authentication type. A BMC that advertises None for the requested
// privilege level may also accept the RMCP+ Open Session Request with
// cipher suite 0 — but we still send the actual probe in
// cipherzero.go because the bitmap is only the channel default;
// per-user configuration can override it.
func (c AuthCapabilities) SupportsCipherZero() bool {
	return c.AuthNone
}

// ParseAuthCapabilities parses the raw UDP response to a
// Get-Channel-Auth-Capabilities request. The IPMI 2.0 spec lays the
// reply out as:
//
//	RMCP header  (4 bytes)
//	IPMI v1.5 session header  (10 bytes, session ID == 0)
//	IPMB message length       (1 byte)
//	IPMB response  (varies):
//	  rqAddr, netfn|lun, chk1, rsAddr, rsSeq|lun, cmd echo (0x38), cc,
//	  channel#, auth_type_support_1, auth_type_support_2,
//	  auth_type_support_3, OEM_id[3], OEM_aux, chk2
//
// All of the bits the deep probe cares about live in bytes 22-24 of
// the response (channel + the three auth-type-support bytes). If we
// can read those, we return a fully-populated struct. If only the
// classic v1.5 byte (auth_type_support_1) is available, we return a
// partial struct.
//
// The wire offsets here are absolute into the response buffer so the
// caller does not have to know how the IPMB message length byte
// stacks with the session header.
func ParseAuthCapabilities(resp []byte) (AuthCapabilities, error) {
	if err := ParseRMCPHeader(resp); err != nil {
		return AuthCapabilities{}, err
	}
	// IPMI v1.5 unauthenticated session header is 10 bytes after the
	// 4-byte RMCP envelope; the IPMB message starts at offset 14.
	const ipmbStart = RMCPHeaderSize + IPMI15SessionHeaderSize

	// Need at least through Auth-Type-Support-1 (data byte 2 of the
	// response payload, absolute offset 22). The parser reads cmd echo
	// (offset 19), completion code (20), channel (21), and bitmap1
	// (22) unconditionally, so we require at least 23 bytes —
	// `ipmbStart + 9` covers offsets 0..(ipmbStart+8) = 0..22.
	if len(resp) < ipmbStart+9 {
		return AuthCapabilities{}, fmt.Errorf("%w: auth-caps reply needs >=%d bytes, got %d",
			ErrTruncatedResponse, ipmbStart+9, len(resp))
	}

	// IPMB response framing sanity. Byte at ipmbStart+5 (offset 19)
	// must be the command echo for Get-Channel-Auth-Caps (0x38). If
	// it isn't, the response we got was for a different command and
	// the data offsets won't be where we expect.
	if resp[ipmbStart+5] != getChannelAuthCapsCommand {
		return AuthCapabilities{}, fmt.Errorf("auth-caps: response is for command 0x%02x, not 0x38", resp[ipmbStart+5])
	}

	// Completion code (offset 20) must be 0x00. Anything else means
	// the BMC rejected the request and the response data bytes are
	// not present.
	if cc := resp[ipmbStart+6]; cc != 0x00 {
		return AuthCapabilities{}, fmt.Errorf("auth-caps: BMC completion code 0x%02x", cc)
	}

	caps := AuthCapabilities{
		ChannelNumber: resp[ipmbStart+7], // offset 21
	}

	// Auth-Type-Support-1 (offset 22) — always present in any
	// well-formed auth-caps reply (this is the field the old plugin
	// got wrong — it read offset 4 instead).
	bitmap1 := resp[ipmbStart+8]
	caps.AuthNone = bitmap1&0x01 != 0
	caps.AuthMD2 = bitmap1&0x02 != 0
	caps.AuthMD5 = bitmap1&0x04 != 0
	caps.AuthStraight = bitmap1&0x10 != 0
	caps.AuthOEM = bitmap1&0x20 != 0
	caps.IPMI20ExtendedCapabilities = bitmap1&0x80 != 0
	caps.Bitmap1Parsed = true

	// Auth-Type-Support-2 (offset 23) — present whenever the response
	// payload includes byte ipmbStart+9. v1.5-only BMCs may truncate
	// here; we keep the partial result instead of erroring.
	if len(resp) >= ipmbStart+10 {
		bitmap2 := resp[ipmbStart+9]
		caps.AnonymousLoginEnabled = bitmap2&0x01 != 0
		caps.NullUsernameEnabled = bitmap2&0x02 != 0
		caps.NonNullUsernameEnabled = bitmap2&0x04 != 0
		caps.UserLevelAuthDisabled = bitmap2&0x08 != 0
		caps.PerMessageAuthDisabled = bitmap2&0x10 != 0
		caps.KgSet = bitmap2&0x20 != 0
		caps.Bitmap2Parsed = true
	}

	// Auth-Type-Support-3 (offset 24) — IPMI 2.0 only. When the BMC
	// did not include this byte, we leave IPMI15/20Supported false
	// and Version() falls back to "1.5".
	if len(resp) >= ipmbStart+11 {
		bitmap3 := resp[ipmbStart+10]
		caps.IPMI15Supported = bitmap3&0x01 != 0
		caps.IPMI20Supported = bitmap3&0x02 != 0
		caps.Bitmap3Parsed = true
	}

	// OEM ID (offsets 25-27) — LSB-first 24-bit value. Only present
	// alongside Auth-Type-Support-3 in the 2.0 extended response.
	if len(resp) >= ipmbStart+14 {
		caps.OEMID = uint32(resp[ipmbStart+11]) |
			uint32(resp[ipmbStart+12])<<8 |
			uint32(resp[ipmbStart+13])<<16
		caps.OEMIDParsed = true
	}

	return caps, nil
}

// CopyAuthTypeSupport1 returns the raw Auth-Type-Support-1 byte from
// the response, used by the plugin to populate the backward-compatible
// authType string field as a hex literal (e.g. "0x15"). Returns 0x00
// and false if the response is too short.
func CopyAuthTypeSupport1(resp []byte) (byte, bool) {
	const offset = RMCPHeaderSize + IPMI15SessionHeaderSize + 8
	if len(resp) <= offset {
		return 0x00, false
	}
	return resp[offset], true
}
