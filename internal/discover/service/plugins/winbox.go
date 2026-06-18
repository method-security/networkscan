// Package plugins provides Winbox (MikroTik RouterOS management) service fingerprinting
package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

// WinboxFingerprinter detects MikroTik RouterOS Winbox service on TCP/8291.
// It performs a /list probe to extract RouterOS version, board name, and system
// identity.  The probe is read-only and pre-authentication — no credentials are
// ever sent and no modifications are made to the target.
//
// CVE-2018-14847 patch-state validation is intentionally excluded here; it
// belongs in the pentest service layer once that harness is in place.
type WinboxFingerprinter struct{}

func (WinboxFingerprinter) Name() string        { return "winbox" }
func (WinboxFingerprinter) DefaultPorts() []int { return []int{8291} }

func (WinboxFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	if result, err := detectWinboxWithNmapProbes(ctx, ip, port, host, timeout); err == nil {
		return result, nil
	}

	// /list request — get RouterOS version + identity
	listResp, err := helpers.TCPExchange(ctx, ip, port, timeout, buildWinboxListRequest(), 4096)
	if err != nil {
		return nil, err
	}
	if !looksLikeWinbox(listResp) {
		return nil, fmt.Errorf("not Winbox")
	}
	routerosVersion, boardName, boardIdentity := parseWinboxList(listResp)

	metadata := &protocol.WinboxServerInfo{
		RouterosVersion: stringPtr(routerosVersion),
		BoardName:       stringPtr(boardName),
		BoardIdentity:   stringPtr(boardIdentity),
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeWinbox,
		Version:   stringPtr(routerosVersion),
		Metadata:  &discoverfern.ServiceMetadata{Winbox: metadata},
	}, nil
}

func detectWinboxWithNmapProbes(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	probes := []struct {
		name    string
		version string
		probe   []byte
		match   func([]byte) bool
	}{
		{
			name:    "modern",
			version: "RouterOS >=6.43",
			probe:   buildWinboxModernProbe(),
			match:   looksLikeModernWinboxProbeResponse,
		},
		{
			name:    "legacy",
			version: "RouterOS <6.43",
			probe:   buildWinboxLegacyProbe(),
			match:   looksLikeLegacyWinboxProbeResponse,
		},
	}

	for _, p := range probes {
		resp, err := helpers.TCPExchange(ctx, ip, port, timeout, p.probe, 512)
		if err != nil {
			continue
		}
		if !p.match(resp) {
			continue
		}
		metadata := &protocol.WinboxServerInfo{
			RouterosVersion: stringPtr(p.version),
		}
		return &discoverfern.ServiceDetails{
			Host:      host,
			Ip:        ip.String(),
			Port:      port,
			Tls:       false,
			Transport: common.TransportTypeTcp,
			Protocol:  common.ProtocolTypeWinbox,
			Version:   stringPtr(p.version),
			Metadata:  &discoverfern.ServiceMetadata{Winbox: metadata},
		}, nil
	}
	return nil, fmt.Errorf("not Winbox")
}

func buildWinboxModernProbe() []byte {
	probe := make([]byte, 36)
	probe[0] = 0x22
	probe[1] = 0x06
	return probe
}

func buildWinboxLegacyProbe() []byte {
	probe := make([]byte, 250)
	probe[0] = 0xf8
	probe[1] = 0x05
	return probe
}

func looksLikeModernWinboxProbeResponse(resp []byte) bool {
	return len(resp) == 35 &&
		resp[0] == 0x21 &&
		resp[1] == 0x06 &&
		(resp[34] == 0x00 || resp[34] == 0x01)
}

func looksLikeLegacyWinboxProbeResponse(resp []byte) bool {
	if len(resp) != 250 || resp[0] != 0xf8 || resp[1] != 0x05 {
		return false
	}
	for _, b := range resp[2:] {
		if b != 0x00 {
			return true
		}
	}
	return false
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
		end := len(resp)
		if end > 32 {
			end = 32
		}
		return bytes.Contains(resp[:end], []byte{0x4d, 0x32})
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
//   - Identity is any non-empty printable ASCII substring of >= 4 chars that
//     is not the version or board name
//
// Uses a two-pass approach: pass 1 identifies version and board; pass 2 picks
// identity from the remaining strings.  This avoids assigning short
// framing-noise bytes (e.g. "M2") as the identity before the real system name
// appears later in the response.
func parseWinboxList(resp []byte) (version, boardName, identity string) {
	strs := extractASCIIStrings(resp, 2)

	// Pass 1: identify version and board name from the full string list.
	for _, s := range strs {
		s = strings.TrimSpace(s)
		if version == "" && looksLikeROSVersion(s) {
			version = s
		}
		if boardName == "" && looksLikeBoardName(s) {
			boardName = s
		}
		if version != "" && boardName != "" {
			break
		}
	}

	// Pass 2: pick identity from strings that are neither version nor board
	// and are at least 4 printable chars.  Minimum length of 4 avoids
	// protocol-framing artifacts ("M2") that precede the system name field.
	for _, s := range strs {
		s = strings.TrimSpace(s)
		if s == "" || s == version || s == boardName {
			continue
		}
		if len(s) >= 4 && len(s) <= 64 && isPrintableASCII(s) &&
			!looksLikeROSVersion(s) && !looksLikeBoardName(s) {
			identity = s
			break
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
