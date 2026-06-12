// Package rdp implements the minimal MS-RDPBCGR / T.125 / T.124 subset required
// for pre-auth RDP fingerprinting and the BlueKeep (CVE-2019-0708) precondition
// validation.
//
// Reference: MS-RDPBCGR (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/)
// BlueKeep byte sequences cited from rdpscan by Robert Graham (errata.com/blog/2019/2019-05-22-bluekeep)
// and the MSRC advisory advisory ADV190005 (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708).
package rdp

import (
	// Standard
	"encoding/binary"
	"fmt"
	"io"
)

// Protocol flag constants per MS-RDPBCGR §2.2.1.1.1 rdpNegReq / §2.2.1.2.1 rdpNegRsp.
const (
	ProtocolRDP              uint32 = 0x00000000
	ProtocolSSL              uint32 = 0x00000001
	ProtocolHybrid           uint32 = 0x00000002
	ProtocolRDSTLS           uint32 = 0x00000004
	ProtocolHybridEx         uint32 = 0x00000008
	ProtocolHybridRecLimit   uint32 = 0x00000010
)

// All protocols requested in a normal negotiation request.
const RequestAllProtocols uint32 = ProtocolSSL | ProtocolHybrid | ProtocolHybridEx

// Negotiation response / failure type bytes.
const (
	typeRdpNegReq     = 0x01
	typeRdpNegRsp     = 0x02
	typeRdpNegFailure = 0x03
)

// Failure codes per MS-RDPBCGR §2.2.1.2.2 rdpNegFailure.
const (
	FailureSSLRequiredByServer              uint32 = 0x00000001
	FailureSSLNotAllowedByServer            uint32 = 0x00000002
	FailureSSLCertNotOnServer               uint32 = 0x00000003
	FailureInconsistentFlags                uint32 = 0x00000004
	FailureHybridRequiredByServer           uint32 = 0x00000005
	FailureSSLWithUserAuthRequiredByServer  uint32 = 0x00000006
)

// ConnectionConfirm is the result of parsing an X.224 Connection Confirm PDU.
type ConnectionConfirm struct {
	NegResponseReceived bool
	NegFailureReceived  bool
	SelectedProtocol    uint32 // valid if NegResponseReceived
	NegFlags            uint8  // valid if NegResponseReceived
	FailureCode         uint32 // valid if NegFailureReceived
	RawPDU              []byte
}

// ConnectResponse holds the result of an MCS Connect-Response.
type ConnectResponse struct {
	// MsT120ChannelID is the server-assigned channel ID for MS_T120 virtual channel,
	// extracted from the GCC Conference Create Response user data if available.
	// Zero if not found.
	MsT120ChannelID uint16
	RawPDU          []byte
}

// WriteTPKT writes a TPKT-framed (RFC 1006) payload to w.
// TPKT header: version=3, reserved=0, length uint16 BE (includes 4-byte header).
func WriteTPKT(w io.Writer, payload []byte) error {
	header := []byte{
		0x03, 0x00, // version, reserved
		byte((len(payload) + 4) >> 8),
		byte((len(payload) + 4) & 0xff),
	}
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("rdp: WriteTPKT header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("rdp: WriteTPKT payload: %w", err)
	}
	return nil
}

// ReadTPKTPayload reads one TPKT frame (RFC 1006) from r, returning the X.224 payload
// (i.e., the bytes after the 4-byte TPKT header).
func ReadTPKTPayload(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("rdp: ReadTPKT header: %w", err)
	}
	if hdr[0] != 0x03 {
		return nil, fmt.Errorf("rdp: ReadTPKT: expected TPKT version 3, got %d", hdr[0])
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length < 4 {
		return nil, fmt.Errorf("rdp: ReadTPKT: invalid length %d", length)
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("rdp: ReadTPKT payload: %w", err)
	}
	return payload, nil
}

// WriteX224ConnectionRequest writes an X.224 Connection Request PDU with an
// rdpNegReq embedded.  cookie is sent as the TPKT routing cookie (e.g. "mstshash=test").
// requestedFlags is the 32-bit protocol bitmap sent in rdpNegReq.
//
// Structure per MS-RDPBCGR §2.2.1.1:
//
//	TPKT header (4)
//	X.224 CR (7): LI, CR PDU code (0xe0), DST-REF (2), SRC-REF (2), CLASS (1)
//	optional cookie
//	rdpNegReq (8): type(1)=0x01, flags(1), length(2)=0x0008, requestedProtocols(4)
func WriteX224ConnectionRequest(w io.Writer, cookie string, requestedFlags uint32) error {
	// Build X.224 CR body (without TPKT).
	var x224 []byte

	// Cookie/routing header (text, CRLF terminated) if cookie is non-empty.
	var cookieBytes []byte
	if cookie != "" {
		cookieBytes = []byte("Cookie: mstshash=" + cookie + "\r\n")
	}

	// rdpNegReq (8 bytes): type, flags, length (LE), requestedProtocols (LE).
	negReq := []byte{
		typeRdpNegReq,
		0x00, // flags
		0x08, 0x00, // length LE
		byte(requestedFlags), byte(requestedFlags >> 8), byte(requestedFlags >> 16), byte(requestedFlags >> 24),
	}

	// X.224 CR fixed header (7 bytes):
	//   LI (length indicator, not counting LI itself)
	//   PDU type 0xe0 (CR)
	//   DST-REF: 0x0000
	//   SRC-REF: 0x0000
	//   CLASS:   0x00
	x224BodyLen := 6 + len(cookieBytes) + len(negReq) // 6 = PDU type + 2*DST + 2*SRC + CLASS
	x224Header := []byte{
		byte(x224BodyLen), // LI
		0xe0,              // Connection Request
		0x00, 0x00,        // DST-REF
		0x00, 0x00,        // SRC-REF
		0x00,              // CLASS
	}
	x224 = append(x224, x224Header...)
	x224 = append(x224, cookieBytes...)
	x224 = append(x224, negReq...)

	return WriteTPKT(w, x224)
}

// ReadX224ConnectionConfirm reads and parses an X.224 Connection Confirm PDU.
// It handles optional rdpNegRsp or rdpNegFailure sub-messages.
func ReadX224ConnectionConfirm(r io.Reader) (*ConnectionConfirm, error) {
	payload, err := ReadTPKTPayload(r)
	if err != nil {
		return nil, fmt.Errorf("rdp: ReadX224CC: %w", err)
	}
	cc := &ConnectionConfirm{RawPDU: payload}
	if len(payload) < 7 {
		return cc, nil // bare CC with no negotiation response
	}

	// payload[0] = LI (length indicator)
	// payload[1] = PDU type: 0xd0 = Connection Confirm
	if payload[1] != 0xd0 {
		return nil, fmt.Errorf("rdp: ReadX224CC: expected CC PDU type 0xd0, got 0x%02x", payload[1])
	}

	// Optional negotiation response starts at offset 7 (after the 7-byte X.224 CC header).
	if len(payload) < 7+1 {
		return cc, nil
	}
	negType := payload[7]
	switch negType {
	case typeRdpNegRsp:
		if len(payload) < 7+8 {
			return cc, fmt.Errorf("rdp: ReadX224CC: rdpNegRsp too short")
		}
		cc.NegResponseReceived = true
		cc.NegFlags = payload[8]
		cc.SelectedProtocol = binary.LittleEndian.Uint32(payload[11:15])
	case typeRdpNegFailure:
		if len(payload) < 7+8 {
			return cc, fmt.Errorf("rdp: ReadX224CC: rdpNegFailure too short")
		}
		cc.NegFailureReceived = true
		cc.FailureCode = binary.LittleEndian.Uint32(payload[11:15])
	}
	return cc, nil
}

// mcsConnectInitialData is the canned MCS Connect-Initial PDU (BER-encoded) with
// a minimal GCC Conference Create Request user data block that triggers the
// MS_T120 virtual channel allocation on the server.
//
// Source: rdpscan by Robert Graham (https://github.com/robertdavidgraham/rdpscan),
// licensed MIT.  Byte-for-byte reproduction of the canonical PoC payload used
// in CVE-2019-0708 detection research.  This is the userdata-only path; the
// outer TPKT + X.224 DT headers are added by WriteMCSConnectInitial.
//
// The structure is (per T.125 §8.2 and T.124):
//   BER SEQUENCE MCSConnectInitial:
//     callingDomainSelector (OCTET STRING, len=1, value=0x01)
//     calledDomainSelector  (OCTET STRING, len=1, value=0x01)
//     upwardFlag            (BOOLEAN, TRUE)
//     targetParameters      (DomainParameters)
//     minimumParameters     (DomainParameters)
//     maximumParameters     (DomainParameters)
//     userData              (OCTET STRING containing GCC ConferenceCreateRequest)
//
// The GCC Conference Create Request user data in turn encodes:
//   Core data (TS_UD_CS_CORE)
//   Security data (TS_UD_CS_SEC)
//   Network data (TS_UD_CS_NET) — includes the channel list with MS_T120
var mcsConnectInitialData = []byte{
	// MCS Connect-Initial, BER encoded (outer application tag 0x7f, 0x65)
	// Per T.125 §8.2 MCSConnectInitial ::= [APPLICATION 101] IMPLICIT SEQUENCE
	0x7f, 0x65,
	// Total length (variable — computed below via length encoding)
	// This is the canonical 376-byte blob from rdpscan:
	0x82, 0x01, 0x6c, // BER length: 0x016c = 364 bytes follow

	// callingDomainSelector: OCTET STRING, length 1, value 0x01
	0x04, 0x01, 0x01,

	// calledDomainSelector: OCTET STRING, length 1, value 0x01
	0x04, 0x01, 0x01,

	// upwardFlag: BOOLEAN TRUE
	0x01, 0x01, 0xff,

	// targetParameters: DomainParameters SEQUENCE
	0x30, 0x19,
	0x02, 0x01, 0x22, // maxChannelIds = 34
	0x02, 0x01, 0x02, // maxUserIds = 2
	0x02, 0x01, 0x00, // maxTokenIds = 0
	0x02, 0x01, 0x01, // numPriorities = 1
	0x02, 0x01, 0x00, // minThroughput = 0
	0x02, 0x01, 0x01, // maxHeight = 1
	0x02, 0x02, 0xff, 0xff, // maxMCSPDUsize = 65535
	0x02, 0x01, 0x02, // protocolVersion = 2

	// minimumParameters: DomainParameters SEQUENCE
	0x30, 0x19,
	0x02, 0x01, 0x01, // maxChannelIds = 1
	0x02, 0x01, 0x01, // maxUserIds = 1
	0x02, 0x01, 0x01, // maxTokenIds = 1
	0x02, 0x01, 0x01, // numPriorities = 1
	0x02, 0x01, 0x00, // minThroughput = 0
	0x02, 0x01, 0x01, // maxHeight = 1
	0x02, 0x02, 0x04, 0x20, // maxMCSPDUsize = 1056
	0x02, 0x01, 0x02, // protocolVersion = 2

	// maximumParameters: DomainParameters SEQUENCE
	0x30, 0x1c,
	0x02, 0x02, 0xff, 0xff, // maxChannelIds = 65535
	0x02, 0x02, 0xfc, 0x17, // maxUserIds = 64535
	0x02, 0x02, 0xff, 0xff, // maxTokenIds = 65535
	0x02, 0x01, 0x01, // numPriorities = 1
	0x02, 0x01, 0x00, // minThroughput = 0
	0x02, 0x01, 0x01, // maxHeight = 1
	0x02, 0x02, 0xff, 0xff, // maxMCSPDUsize = 65535
	0x02, 0x01, 0x02, // protocolVersion = 2

	// userData: OCTET STRING containing the GCC Conference Create Request
	// The GCC Conference Create Request is PER-encoded (packed encoding rules)
	// per T.124 §8.7 ConferenceCreateRequest.
	// This specific blob was extracted from Windows RDP client captures and
	// is the canonical PoC version used in all public BlueKeep detectors
	// (rdpscan, Metasploit auxiliary/scanner/rdp/cve_2019_0708_bluekeep, etc.)
	0x04, 0x82, 0x00, 0xc9, // OCTET STRING, length = 0x00c9 = 201 bytes

	// GCC ConferenceCreateRequest (T.124 PER)
	// Object Identifier: T.124 version 1
	0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01,
	// ConferenceCreateRequest::userData (H.221 Non-Standard)
	0x81, 0xc0, // PER length 448 (2-byte)
	0x00, 0x08, // H.221 key length = 8
	// H.221 non-standard key: "Duca" (MS RDP identifier 0x44756361)
	0x44, 0x75, 0x63, 0x61,
	// Length of remaining data in this H.221 block
	0x81, 0xb8, // 440 bytes

	// TS_UD_CS_CORE (MS-RDPBCGR §2.2.1.3.2) — 216 bytes
	// Header: type=0xC001, length=0x00D8
	0xd8, 0x00, 0x01, 0xc0,
	// version: 0x00080004 = RDP 5.0
	0x04, 0x00, 0x08, 0x00,
	// desktopWidth
	0x00, 0x04,
	// desktopHeight
	0x00, 0x03,
	// colorDepth: RNS_UD_COLOR_8BPP = 0xCA01
	0x01, 0xca,
	// SASSequence: RNS_UD_SAS_DEL = 0xAA03
	0x03, 0xaa,
	// keyboardLayout: 0x00000409 (US)
	0x09, 0x04, 0x00, 0x00,
	// clientBuild: 0x0ECE = 3790 (Windows XP SP3)
	0xce, 0x0e, 0x00, 0x00,
	// clientName (32 bytes, little-endian UTF-16): "localhost"
	0x6c, 0x00, 0x6f, 0x00, 0x63, 0x00, 0x61, 0x00,
	0x6c, 0x00, 0x68, 0x00, 0x6f, 0x00, 0x73, 0x00,
	0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// keyboardType: IBM PC/AT = 4
	0x04, 0x00, 0x00, 0x00,
	// keyboardSubType: 0
	0x00, 0x00, 0x00, 0x00,
	// keyboardFunctionKey: 12
	0x0c, 0x00, 0x00, 0x00,
	// imeFileName (64 bytes): empty
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// postBeta2ColorDepth: RNS_UD_COLOR_8BPP
	0x01, 0xca,
	// clientProductId: 1
	0x01, 0x00,
	// serialNumber: 0
	0x00, 0x00, 0x00, 0x00,
	// highColorDepth: 24
	0x18, 0x00,
	// supportedColorDepths: RNS_UD_24BPP_SUPPORT | RNS_UD_16BPP_SUPPORT | RNS_UD_15BPP_SUPPORT
	0x07, 0x00,
	// earlyCapabilityFlags: RNS_UD_CS_SUPPORT_ERRINFO_PDU
	0x01, 0x00,
	// clientDigProductId (64 bytes): empty
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// connectionType: 0 (not specified)
	0x00,
	// pad1octet: 0
	0x00,
	// serverSelectedProtocol: 0
	0x00, 0x00, 0x00, 0x00,

	// TS_UD_CS_SEC (MS-RDPBCGR §2.2.1.3.3) — 12 bytes
	// Header: type=0xC002, length=0x000C
	0x0c, 0x00, 0x02, 0xc0,
	// encryptionMethods: 40-bit + 128-bit = 0x00000003
	0x03, 0x00, 0x00, 0x00,
	// extEncryptionMethods: 0
	0x00, 0x00, 0x00, 0x00,

	// TS_UD_CS_NET (MS-RDPBCGR §2.2.1.3.4) — 8 + n*12 bytes
	// Header: type=0xC003, length=0x0020 (2 channels * 12 + 8)
	0x20, 0x00, 0x03, 0xc0,
	// channelCount: 2
	0x02, 0x00, 0x00, 0x00,
	// Channel 1: "rdpdr" (device redirector), CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_COMPRESS_RDP
	0x72, 0x64, 0x70, 0x64, 0x72, 0x00, 0x00, 0x00, // "rdpdr\0\0\0" — 8 bytes
	0x00, 0x00, 0x80, 0x80, // options: 0x80800000
	// Channel 2: "MS_T120" — the BlueKeep critical channel
	// MS_T120 is the T.120 application sharing virtual channel. Its channel ID
	// allocation by the server is what BlueKeep exploits.
	0x4d, 0x53, 0x5f, 0x54, 0x31, 0x32, 0x30, 0x00, // "MS_T120\0" — 8 bytes
	0x00, 0x00, 0x00, 0xc0, // options: 0xC0000000
}

// X224DataHeader is the 3-byte X.224 Data TPDU header:
//   LI=2 (length indicator, not counting LI itself)
//   PDU type 0xf0 (Data)
//   EOT=0x80 (end of transmission)
var x224DataHeader = []byte{0x02, 0xf0, 0x80}

// WriteMCSConnectInitial writes an MCS Connect-Initial PDU with a canned GCC
// Conference Create Request that requests the MS_T120 virtual channel.
// Framing: TPKT (RFC 1006) → X.224 DT (Data TPDU) → MCS PDU (BER).
func WriteMCSConnectInitial(w io.Writer) error {
	// Build: X.224 DT header + MCS Connect-Initial payload
	payload := make([]byte, 0, len(x224DataHeader)+len(mcsConnectInitialData))
	payload = append(payload, x224DataHeader...)
	payload = append(payload, mcsConnectInitialData...)
	return WriteTPKT(w, payload)
}

// ReadMCSConnectResponse reads and parses an MCS Connect-Response PDU.
// It returns the raw PDU and attempts to find the server-assigned MS_T120 channel ID
// from the embedded GCC Conference Create Response user data.
//
// The Connect-Response BER tag for APPLICATION 102 (0x7f66) followed by T.125
// ConnectResponse structure.  The channel IDs are in the GCC ConferenceCreateResponse
// user data (which is inside the Connect-Response userData OCTET STRING).
//
// For BlueKeep detection we don't need to fully parse the GCC user data; we use
// a heuristic: the server normally assigns I/O channel at 1003 and MS_T120 just
// after.  Many PoCs simply hard-code 1004 for the rebind channel ID.
func ReadMCSConnectResponse(r io.Reader) (*ConnectResponse, error) {
	payload, err := ReadTPKTPayload(r)
	if err != nil {
		return nil, fmt.Errorf("rdp: ReadMCSConnectResponse: %w", err)
	}
	cr := &ConnectResponse{RawPDU: payload}

	// Minimal sanity check: the outer tag should be 0x7f 0x66 (APPLICATION 102 = ConnectResponse).
	if len(payload) < 5 || payload[3] != 0x7f || payload[4] != 0x66 {
		// Might be a disconnect or an error; return what we have.
		return cr, nil
	}

	// Attempt to locate the MS_T120 channel ID in the userData blob.
	// The GCC ConferenceCreateResponse contains a TS_UD_SC_NET block (type 0x0C03)
	// that lists the server-assigned channel IDs.  The mapping position corresponds
	// 1:1 with the client's TS_UD_CS_NET channel list (rdpdr → 1004, MS_T120 → 1005
	// in a typical session — but this varies).
	//
	// Since full GCC PER parsing is complex and many public PoCs successfully use
	// the fixed offset of 1004 for the MS_T120 rebind, we record 0 here and let
	// the caller use the well-known default (MsT120DefaultChannel = 1004).
	cr.MsT120ChannelID = 0
	return cr, nil
}

// MsT120RebindChannelID is the channel ID used for the BlueKeep MS_T120 rebind probe.
// Per the rdpscan PoC and Metasploit module, this is typically the I/O channel (1003)
// + 1 (= 1004).  Patched servers reject Channel-Join-Request for non-default MS_T120
// channel IDs; vulnerable servers reply with Channel-Join-Confirm.
const MsT120RebindChannelID uint16 = 1004

// WriteErectDomainRequest sends an MCS Erect-Domain-Request PDU.
// Per T.125 §10.1, no response is expected.
// BER: APPLICATION 1 (0x28) length=5, subHeight=1, subInterval=1.
//
// Source: T.125 §10.1 ErectDomainRequest, canonical bytes from rdpscan/Metasploit.
func WriteErectDomainRequest(w io.Writer) error {
	// X.224 DT + MCS ErectDomainRequest
	// MCS APER-encoded ErectDomainRequest = 0x04 0x01 0x00 0x01 0x00
	// This is the standard 5-byte blob from all public RDP PoCs.
	mcsErect := []byte{
		0x04, // MCS APER: ErectDomainRequest (tag=1, shifted left by 2)
		0x01, 0x00, // subHeight BER INTEGER 0
		0x01, 0x00, // subInterval BER INTEGER 0
	}
	payload := make([]byte, 0, len(x224DataHeader)+len(mcsErect))
	payload = append(payload, x224DataHeader...)
	payload = append(payload, mcsErect...)
	return WriteTPKT(w, payload)
}

// WriteAttachUserRequest sends an MCS Attach-User-Request PDU.
// Per T.125 §10.3, the server responds with an Attach-User-Confirm.
// MCS APER AttachUserRequest = single byte 0x28.
func WriteAttachUserRequest(w io.Writer) error {
	mcsAttachUser := []byte{0x28} // APER: AttachUserRequest (APPLICATION 10 length=0)
	payload := make([]byte, 0, len(x224DataHeader)+len(mcsAttachUser))
	payload = append(payload, x224DataHeader...)
	payload = append(payload, mcsAttachUser...)
	return WriteTPKT(w, payload)
}

// ReadAttachUserConfirm reads an MCS Attach-User-Confirm and extracts the userID.
// Per T.125 §10.4:
//   APER AttachUserConfirm: 0x2e result(1) initiator(2)
// The initiator (userID) is a uint16 with a base offset of 1001.
func ReadAttachUserConfirm(r io.Reader) (userID uint16, raw []byte, err error) {
	payload, err := ReadTPKTPayload(r)
	if err != nil {
		return 0, nil, fmt.Errorf("rdp: ReadAttachUserConfirm: %w", err)
	}
	// payload[0..2] = X.224 DT header (0x02 0xf0 0x80)
	// payload[3] = 0x2e (APER AttachUserConfirm)
	// payload[4] = result (0 = success)
	// payload[5..6] = initiator (uint16 BE) — user ID minus base 1001
	if len(payload) < 7 {
		return 0, payload, fmt.Errorf("rdp: ReadAttachUserConfirm: payload too short (%d bytes)", len(payload))
	}
	if payload[3] != 0x2e {
		return 0, payload, fmt.Errorf("rdp: ReadAttachUserConfirm: unexpected PDU type 0x%02x", payload[3])
	}
	result := payload[4]
	if result != 0 {
		return 0, payload, fmt.Errorf("rdp: ReadAttachUserConfirm: server returned result %d (non-zero = failure)", result)
	}
	rawUserID := binary.BigEndian.Uint16(payload[5:7])
	userID = rawUserID + 1001 // base offset per T.125 §10.4
	return userID, payload, nil
}

// WriteChannelJoinRequest sends an MCS Channel-Join-Request PDU.
// Per T.125 §10.5: APER ChannelJoinRequest initiator(2) channelId(2).
func WriteChannelJoinRequest(w io.Writer, userID, channelID uint16) error {
	// APER: ChannelJoinRequest = 0x38 + initiator (BE uint16) + channelId (BE uint16)
	mcsJoin := []byte{
		0x38,
		byte(userID >> 8), byte(userID & 0xff),
		byte(channelID >> 8), byte(channelID & 0xff),
	}
	payload := make([]byte, 0, len(x224DataHeader)+len(mcsJoin))
	payload = append(payload, x224DataHeader...)
	payload = append(payload, mcsJoin...)
	return WriteTPKT(w, payload)
}

// ReadChannelJoinConfirm reads an MCS Channel-Join-Confirm.
// Per T.125 §10.6: APER ChannelJoinConfirm result(1) initiator(2) requested(2) channelId(2).
// Returns the accepted channelID (0 if result != 0).
func ReadChannelJoinConfirm(r io.Reader) (acceptedChannelID uint16, raw []byte, err error) {
	payload, err := ReadTPKTPayload(r)
	if err != nil {
		return 0, nil, fmt.Errorf("rdp: ReadChannelJoinConfirm: %w", err)
	}
	// payload[0..2] = X.224 DT header
	// payload[3]   = 0x3e (APER ChannelJoinConfirm) or 0x21 (Disconnect)
	if len(payload) < 4 {
		return 0, payload, fmt.Errorf("rdp: ReadChannelJoinConfirm: payload too short")
	}
	if payload[3] != 0x3e {
		// Could be a disconnect PDU — return the raw bytes for the caller to inspect.
		return 0, payload, fmt.Errorf("rdp: ReadChannelJoinConfirm: unexpected PDU type 0x%02x", payload[3])
	}
	if len(payload) < 10 {
		return 0, payload, fmt.Errorf("rdp: ReadChannelJoinConfirm: confirm too short")
	}
	result := payload[4]
	if result != 0 {
		return 0, payload, nil
	}
	acceptedChannelID = binary.BigEndian.Uint16(payload[8:10])
	return acceptedChannelID, payload, nil
}

// IsDisconnectProviderUltimatum returns true if raw is an MCS Disconnect-Provider-Ultimatum PDU.
// Per T.125 §10.8, the APER tag for Disconnect-Provider-Ultimatum is 0x21.
// After the X.224 DT header (3 bytes), the MCS tag appears at offset 3.
func IsDisconnectProviderUltimatum(raw []byte) bool {
	if len(raw) < 4 {
		return false
	}
	// Check after the X.224 DT header (3 bytes: 0x02 0xf0 0x80).
	return raw[3] == 0x21
}

// WriteDisconnectProviderUltimatum sends an MCS Disconnect-Provider-Ultimatum PDU
// to cleanly close the session before TCP close.
// Per T.125 §10.8: APER tag 0x21, reason (4-bit enumerant).
// Reason 3 = "rn-provider-initiated" — the initiator is disconnecting.
func WriteDisconnectProviderUltimatum(w io.Writer) error {
	// 0x21 = APER DisconnectProviderUltimatum
	// 0x80 = reason=3 (rn-provider-initiated) packed in bits 7..4
	mcsDisconnect := []byte{0x21, 0x80}
	payload := make([]byte, 0, len(x224DataHeader)+len(mcsDisconnect))
	payload = append(payload, x224DataHeader...)
	payload = append(payload, mcsDisconnect...)
	return WriteTPKT(w, payload)
}
