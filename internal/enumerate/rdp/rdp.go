// Package rdp implements RDP pre-auth enumeration via X.224/TPKT negotiation.
// Scope A (Scope B is excluded): NO authentication, NO CredSSP/NLA handshake.
// We probe connectivity, perform the rdpNeg handshake, and optionally capture
// the TLS certificate when the server selects SSL/HYBRID/HYBRID_EX/RDSTLS/RDS_AAD_AUTH.
package rdp

import (
	// Standard
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	// Generated — from this repo's generated Go types
	protocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	rdpfern "github.com/Method-Security/networkscan/generated/go/enumerate/rdp"

	// Internal
	"github.com/Method-Security/networkscan/utils"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const (
	defaultRDPPort      = 3389
	defaultPortRangeStr = "3389"
	rdpHandshakeTimeout = 10 * time.Second

	// MS-RDPBCGR §2.2.1.1 — requested protocol bitmask values
	protocolRDP      = uint32(0x00000000)
	protocolSSL      = uint32(0x00000001)
	protocolHybrid   = uint32(0x00000002)
	protocolRDSTLS   = uint32(0x00000004)
	protocolHybridEx = uint32(0x00000008)
	protocolRDSAAD   = uint32(0x00000010)

	// rdpNeg PDU types
	rdpNegTypeRequest  = byte(0x01)
	rdpNegTypeResponse = byte(0x02)
	rdpNegTypeFailure  = byte(0x03)
)

// requestedProtocols is the combined bitmask we send in the initial CR PDU,
// asking the server to select its highest-supported protocol. We request all
// known non-legacy protocols per MS-RDPBCGR §2.2.1.1.
//
//	SSL | HYBRID | RDSTLS | HYBRID_EX | RDS_AAD_AUTH
var requestedProtocols = protocolSSL | protocolHybrid | protocolRDSTLS | protocolHybridEx | protocolRDSAAD

// securityProtocolMap maps wire values to the generated enum type.
var securityProtocolMap = map[uint32]protocolfern.RdpSecurityProtocol{
	protocolRDP:      protocolfern.RdpSecurityProtocolStandardRdp,
	protocolSSL:      protocolfern.RdpSecurityProtocolSsl,
	protocolHybrid:   protocolfern.RdpSecurityProtocolHybrid,
	protocolRDSTLS:   protocolfern.RdpSecurityProtocolRdstls,
	protocolHybridEx: protocolfern.RdpSecurityProtocolHybridEx,
	protocolRDSAAD:   protocolfern.RdpSecurityProtocolRdsAadAuth,
}

// negFailureMap maps rdpNegFailure codes to the generated enum type.
var negFailureMap = map[uint32]protocolfern.RdpNegotiationFailure{
	0x00000001: protocolfern.RdpNegotiationFailureSslRequiredByServer,
	0x00000002: protocolfern.RdpNegotiationFailureSslNotAllowedByServer,
	0x00000003: protocolfern.RdpNegotiationFailureSslCertNotOnServer,
	0x00000004: protocolfern.RdpNegotiationFailureInconsistentFlags,
	0x00000005: protocolfern.RdpNegotiationFailureHybridRequiredByServer,
	0x00000006: protocolfern.RdpNegotiationFailureSslWithUserAuthRequiredByServer,
}

// LibraryEnumerateRDP implements NetworkApplicationLibrary for RDP pre-auth enumeration.
type LibraryEnumerateRDP struct {
	PortRange string
}

// EnumerateTarget performs RDP pre-auth enumeration against a single target.
//
// Flow:
//  1. Parse target; if no port given, sweep portRange (default 3389)
//  2. Dial TCP; set canConnect=true on success
//  3. Send X.224 CR PDU + rdpNeg request for all supported protocols
//  4. Parse X.224 CC PDU — rdpNegRsp (type=0x02) or rdpNegFailure (type=0x03)
//  5. If failure HYBRID_REQUIRED_BY_SERVER, retry requesting HYBRID only
//  6. If negotiated protocol requires TLS: upgrade and capture server cert
//  7. Derive nlaRequired = (negotiated in {HYBRID, HYBRID_EX})
func (l *LibraryEnumerateRDP) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting RDP enumeration", svc1log.SafeParam("target", target))

	errors := []string{}

	host, port := utils.ParseHostPort(target, 0)
	hasExplicitPort := (port != 0)

	// Build list of ports to probe. If no explicit port, sweep the configured
	// range. A malformed --rdp-port-range must NOT silently degrade; surface
	// the error and fall back to the default single-port so we still probe 3389.
	var ports []int
	if hasExplicitPort {
		ports = []int{port}
	} else {
		portRange := l.PortRange
		if portRange == "" {
			portRange = defaultPortRangeStr
		}
		ports = parsePortRange(portRange)
		if len(ports) == 0 {
			errors = append(errors, fmt.Sprintf(
				"invalid --rdp-port-range %q (expected NNNN or NNNN-MMMM with 1-65535); falling back to %s",
				portRange, defaultPortRangeStr))
			ports = parsePortRange(defaultPortRangeStr)
			if len(ports) == 0 {
				ports = []int{defaultRDPPort}
			}
		}
	}

	var allDetails []*rdpfern.EnumerateRdpDetails
	for _, p := range ports {
		if err := ctx.Err(); err != nil {
			errors = append(errors, fmt.Sprintf("port %d: ctx: %v", p, err))
			break
		}
		detail := probePort(ctx, log, host, p)
		allDetails = append(allDetails, detail)
		if detail.Errors != nil {
			for _, e := range detail.Errors {
				errors = append(errors, fmt.Sprintf("port %d: %s", p, e))
			}
		}
		// Early exit on first port that completed the X.224 handshake
		if detail.ServerInfo != nil && detail.ServerInfo.X224Reachable != nil && *detail.ServerInfo.X224Reachable {
			break
		}
	}

	// Return the best result: prefer ports that completed X.224 handshake
	if len(allDetails) == 1 {
		return &enumeratefern.EnumerateServiceDetails{EnumerateRdpDetails: allDetails[0]}, errors
	}
	// (1) Best: X.224 handshake completed
	for _, d := range allDetails {
		if d.ServerInfo != nil && d.ServerInfo.X224Reachable != nil && *d.ServerInfo.X224Reachable {
			return &enumeratefern.EnumerateServiceDetails{EnumerateRdpDetails: d}, errors
		}
	}
	// (2) TCP connected but handshake did not complete
	for _, d := range allDetails {
		if d.CanConnect != nil && *d.CanConnect {
			return &enumeratefern.EnumerateServiceDetails{EnumerateRdpDetails: d}, errors
		}
	}
	if len(allDetails) > 0 {
		return &enumeratefern.EnumerateServiceDetails{EnumerateRdpDetails: allDetails[len(allDetails)-1]}, errors
	}

	// Fallback — no ports probed (ctx cancelled before loop body ran)
	fallbackPort := defaultRDPPort
	if hasExplicitPort {
		fallbackPort = port
	}
	detail := &rdpfern.EnumerateRdpDetails{Target: target, Port: fallbackPort}
	return &enumeratefern.EnumerateServiceDetails{EnumerateRdpDetails: detail}, errors
}

// probePort performs the RDP pre-auth handshake on a single host:port.
//
// MS-RDPBCGR §2.2.1 negotiation flow:
//  1. Client → Server: X.224 CR PDU with rdpNeg request
//  2. Server → Client: X.224 CC PDU with rdpNegRsp or rdpNegFailure
//  3. If TLS is negotiated: upgrade connection and capture server certificate
//
// No CredSSP/NLA handshake is performed (Scope A only).
func probePort(ctx context.Context, log svc1log.Logger, host string, port int) *rdpfern.EnumerateRdpDetails {
	// Use net.JoinHostPort for IPv6-safe address formatting (not fmt.Sprintf("%s:%d")).
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	target := addr
	detail := &rdpfern.EnumerateRdpDetails{Target: target, Port: port}
	errs := []string{}

	// Determine connection deadline from context or handshake timeout constant
	deadline := time.Now().Add(rdpHandshakeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		canConnect := false
		detail.CanConnect = &canConnect
		errs = append(errs, fmt.Sprintf("rdp connect: %v", err))
		detail.Errors = errs
		return detail
	}
	// The defer captures `conn` by reference (closure), so any later
	// reassignment of conn (e.g. the HYBRID retry path below) is honored —
	// the defer always closes whatever conn points at when this function
	// returns. We deliberately do NOT add a second defer when we re-dial.
	defer func() { _ = conn.Close() }()

	// TCP dial succeeded — record canConnect=true so reports distinguish a
	// reachable host that failed mid-handshake from an entirely unreachable one.
	canConnect := true
	detail.CanConnect = &canConnect

	if err := conn.SetDeadline(deadline); err != nil {
		errs = append(errs, fmt.Sprintf("rdp set deadline: %v", err))
		detail.Errors = errs
		return detail
	}

	serverInfo := &protocolfern.RdpServerInfo{}

	// Attempt handshake with all protocols requested.
	// If server requires HYBRID specifically and rejects our multi-protocol
	// request, retry with only HYBRID. This is documented as a known
	// server behavior per MS-RDPBCGR §2.2.1.2.2.
	negotiated, failureCode, err := doRdpNegHandshake(conn, host, requestedProtocols, deadline)
	if err != nil {
		// If the server returned HYBRID_REQUIRED_BY_SERVER, retry asking for
		// HYBRID alone. We do NOT yet attach the first attempt's failure code
		// to serverInfo — the retry's outcome is authoritative. We only record
		// the first-attempt failure code if the retry fails to connect (so the
		// consumer can still see what we learned about the server's policy).
		if failureCode == protocolfern.RdpNegotiationFailureHybridRequiredByServer {
			firstAttemptFailure := failureCode
			_ = conn.Close()
			conn2, err2 := dialer.DialContext(ctx, "tcp", addr)
			if err2 != nil {
				errs = append(errs, fmt.Sprintf("rdp retry connect: %v", err2))
				x224 := true
				serverInfo.X224Reachable = &x224
				serverInfo.NegotiationFailureCode = firstAttemptFailure.Ptr()
				detail.ServerInfo = serverInfo
				detail.Errors = errs
				return detail
			}
			// The original defer captures `conn` by reference and will close
			// whatever conn points at when probePort returns — assigning conn
			// here is sufficient; do NOT add a second defer or conn2 gets
			// closed twice on the return path.
			conn = conn2
			if err := conn.SetDeadline(deadline); err != nil {
				errs = append(errs, fmt.Sprintf("rdp retry set deadline: %v", err))
				x224 := true
				serverInfo.X224Reachable = &x224
				serverInfo.NegotiationFailureCode = firstAttemptFailure.Ptr()
				detail.ServerInfo = serverInfo
				detail.Errors = errs
				return detail
			}
			negotiated, failureCode, err = doRdpNegHandshake(conn, host, protocolHybrid, deadline)
		}
		if err != nil {
			if failureCode != "" {
				fc := failureCode
				serverInfo.NegotiationFailureCode = fc.Ptr()
				x224 := true
				serverInfo.X224Reachable = &x224
			} else {
				errs = append(errs, fmt.Sprintf("rdp neg handshake: %v", err))
			}
			detail.ServerInfo = serverInfo
			detail.Errors = errs
			return detail
		}
	}

	x224 := true
	serverInfo.X224Reachable = &x224
	proto := negotiated
	serverInfo.NegotiatedSecurityProtocol = proto.Ptr()

	// Derive nlaRequired: HYBRID or HYBRID_EX both mandate CredSSP (NLA)
	nlaRequired := (negotiated == protocolfern.RdpSecurityProtocolHybrid ||
		negotiated == protocolfern.RdpSecurityProtocolHybridEx)
	serverInfo.NlaRequired = &nlaRequired

	// For TLS-capable protocols, upgrade the connection and capture the cert.
	// We skip the upgrade for STANDARD_RDP (no TLS). If failureCode is set
	// but negotiated is still returned, we prioritize the negotiated value.
	if negotiated != protocolfern.RdpSecurityProtocolStandardRdp {
		tlsVersion, cert, tlsErr := grabTLSInfo(conn, host, deadline)
		if tlsErr != nil {
			errs = append(errs, fmt.Sprintf("rdp tls upgrade: %v", tlsErr))
		} else {
			serverInfo.TlsVersion = &tlsVersion
			serverInfo.ServerCertificate = cert
		}
	}

	if failureCode != "" {
		fc := failureCode
		serverInfo.NegotiationFailureCode = fc.Ptr()
	}

	detail.ServerInfo = serverInfo
	detail.Errors = errs
	return detail
}

// doRdpNegHandshake sends an X.224 CR PDU with rdpNeg and reads the X.224 CC PDU.
// Returns the negotiated RdpSecurityProtocol (on success) or a RdpNegotiationFailure code.
// Per MS-RDPBCGR §2.2.1.1 and §2.2.1.2.
func doRdpNegHandshake(conn net.Conn, host string, requestedProto uint32, deadline time.Time) (protocolfern.RdpSecurityProtocol, protocolfern.RdpNegotiationFailure, error) {
	crPDU := buildX224CRPdu(host, requestedProto)
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return "", "", fmt.Errorf("set write deadline: %w", err)
	}
	if _, err := conn.Write(crPDU); err != nil {
		return "", "", fmt.Errorf("write CR PDU: %w", err)
	}

	// Read X.224 CC PDU. Minimum structure:
	//   TPKT header: 4 bytes (version=3, reserved=0, length uint16 BE)
	//   X.224 CC: 7 bytes minimum (length indicator, code 0xD0, dst-ref, src-ref, class)
	//   rdpNeg: 8 bytes (type, flags, length uint16 LE, selectedProtocol/failureCode uint32 LE)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return "", "", fmt.Errorf("set read deadline: %w", err)
	}

	// Read TPKT header (4 bytes)
	tpktHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, tpktHdr); err != nil {
		return "", "", fmt.Errorf("read TPKT header: %w", err)
	}
	if tpktHdr[0] != 0x03 {
		return "", "", fmt.Errorf("unexpected TPKT version: 0x%02x (want 0x03)", tpktHdr[0])
	}
	pktLen := int(binary.BigEndian.Uint16(tpktHdr[2:4]))
	if pktLen < 11 {
		return "", "", fmt.Errorf("TPKT length %d too short (need at least 11)", pktLen)
	}
	// Read the rest of the PDU (pktLen - 4 bytes already consumed)
	rest := make([]byte, pktLen-4)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return "", "", fmt.Errorf("read CC PDU body: %w", err)
	}

	// X.224 CC PDU structure (bytes 0-6 of rest):
	//   [0]  length indicator (LI) — typically 6 or 14 depending on rdpNeg presence
	//   [1]  code = 0xD0 (Connection Confirm)
	//   [2-3] dst-ref
	//   [4-5] src-ref
	//   [6]  class/options
	if len(rest) < 7 {
		return "", "", fmt.Errorf("CC PDU too short (%d bytes after TPKT header)", len(rest))
	}
	if rest[1] != 0xD0 {
		return "", "", fmt.Errorf("unexpected X.224 code: 0x%02x (want 0xD0 CC)", rest[1])
	}

	// rdpNeg optional structure starts at offset 7 of rest (byte 11 overall)
	// Structure: type(1) + flags(1) + length(2 LE) + data(4) = 8 bytes
	if len(rest) < 15 {
		// Server sent a bare CC with no rdpNeg — treat as STANDARD_RDP
		return protocolfern.RdpSecurityProtocolStandardRdp, "", nil
	}

	negType := rest[7]
	// flags := rest[8]  — reserved; we parse but don't use it
	// negLen := binary.LittleEndian.Uint16(rest[9:11])  — should be 8
	negData := binary.LittleEndian.Uint32(rest[11:15])

	switch negType {
	case rdpNegTypeResponse:
		// rdpNegRsp: negData = selectedProtocol
		proto, ok := securityProtocolMap[negData]
		if !ok {
			// Wire value we don't recognise — return as STANDARD_RDP so
			// caller can still attempt TLS upgrade if warranted.
			return protocolfern.RdpSecurityProtocolStandardRdp, "", nil
		}
		return proto, "", nil

	case rdpNegTypeFailure:
		// rdpNegFailure: negData = failureCode
		fc, ok := negFailureMap[negData]
		if !ok {
			return "", "", fmt.Errorf("rdpNegFailure: unknown failure code 0x%08x", negData)
		}
		return "", fc, fmt.Errorf("rdpNegFailure: %s", fc)

	default:
		return "", "", fmt.Errorf("unknown rdpNeg type: 0x%02x", negType)
	}
}

// buildX224CRPdu constructs the TPKT + X.224 CR PDU + rdpNeg request block.
// Per MS-RDPBCGR §2.2.1.1:
//
//	TPKT (4 bytes): version=3, reserved=0, length BE uint16
//	X.224 CR PDU:   LI + code(0xE0) + dst-ref(0x0000) + src-ref(0x0000) + class(0x00)
//	Cookie (optional): "Cookie: mstshash=<routingToken>\r\n" — we send a minimal one
//	rdpNeg:         type=0x01 + flags=0x00 + length=0x0008 LE + requestedProtocols uint32 LE
func buildX224CRPdu(host string, requestedProto uint32) []byte {
	// Cookie: use a minimal mstshash token with the hostname.
	// This is optional but ensures compatibility with Network Policy Servers (NPS)
	// that gate routing on the mstshash field.
	cookie := fmt.Sprintf("Cookie: mstshash=%s\r\n", sanitizeCookieToken(host))
	cookieBytes := []byte(cookie)

	// rdpNeg request: 8 bytes
	rdpNeg := make([]byte, 8)
	rdpNeg[0] = rdpNegTypeRequest                     // type = TYPE_RDP_NEG_REQ
	rdpNeg[1] = 0x00                                  // flags
	binary.LittleEndian.PutUint16(rdpNeg[2:], 0x0008) // length = 8
	binary.LittleEndian.PutUint32(rdpNeg[4:], requestedProto)

	// X.224 CR payload (variable-length user data = cookie + rdpNeg)
	x224Payload := append(cookieBytes, rdpNeg...)
	// X.224 CR header: LI + code + dst-ref(2) + src-ref(2) + class(1) = 6 fixed bytes
	// LI = 6 + len(x224Payload), but X.224 LI covers everything after LI byte itself
	li := byte(6 + len(x224Payload))
	x224Header := []byte{
		li,         // LI
		0xE0,       // CR (Connection Request)
		0x00, 0x00, // dst-ref
		0x00, 0x00, // src-ref
		0x00, // class + options
	}
	x224Body := append(x224Header, x224Payload...)

	// TPKT header: version=3, reserved=0, total length uint16 BE
	totalLen := 4 + len(x224Body)
	tpkt := make([]byte, 4)
	tpkt[0] = 0x03 // version
	tpkt[1] = 0x00 // reserved
	binary.BigEndian.PutUint16(tpkt[2:], uint16(totalLen))

	return append(tpkt, x224Body...)
}

// sanitizeCookieToken strips characters that would break the cookie header.
func sanitizeCookieToken(host string) string {
	// Remove any colons (IPv6) and brackets from the host for cookie use.
	token := strings.NewReplacer(":", "", "[", "", "]", "").Replace(host)
	if len(token) > 64 {
		token = token[:64]
	}
	if token == "" {
		token = "reaper"
	}
	return token
}

// grabTLSInfo upgrades the existing TCP connection to TLS and extracts server
// certificate information. We use InsecureSkipVerify because we are doing
// pre-auth enumeration and the cert may be self-signed (common for RDP).
// This is intentional and documented — the caller knows the risk.
func grabTLSInfo(conn net.Conn, host string, deadline time.Time) (string, *protocolfern.RdpServerCertificate, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // intentional: enumerate only, no auth
		ServerName:         host,
	}
	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.SetDeadline(deadline); err != nil {
		return "", nil, fmt.Errorf("set tls deadline: %w", err)
	}
	if err := tlsConn.Handshake(); err != nil {
		return "", nil, fmt.Errorf("tls handshake: %w", err)
	}

	state := tlsConn.ConnectionState()
	tlsVersion := tlsVersionString(state.Version)

	if len(state.PeerCertificates) == 0 {
		return tlsVersion, nil, nil
	}

	leaf := state.PeerCertificates[0]

	// SHA-256 fingerprint of the raw DER-encoded certificate, formatted as
	// colon-separated uppercase hex pairs (e.g. AA:BB:CC:...).
	fp := sha256.Sum256(leaf.Raw)
	fpParts := make([]string, len(fp))
	for i, b := range fp {
		fpParts[i] = fmt.Sprintf("%02X", b)
	}
	fpFormatted := strings.Join(fpParts, ":")

	notBefore := leaf.NotBefore.UTC().Format(time.RFC3339)
	notAfter := leaf.NotAfter.UTC().Format(time.RFC3339)
	serial := leaf.SerialNumber.String()
	sigAlg := leaf.SignatureAlgorithm.String()
	subject := leaf.Subject.String()
	issuer := leaf.Issuer.String()

	cert := &protocolfern.RdpServerCertificate{
		Subject:            &subject,
		Issuer:             &issuer,
		NotBefore:          &notBefore,
		NotAfter:           &notAfter,
		Sha256Fingerprint:  &fpFormatted,
		SerialNumber:       &serial,
		SignatureAlgorithm: &sigAlg,
	}
	return tlsVersion, cert, nil
}

// tlsVersionString converts a crypto/tls version constant to a human-readable string.
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}

// parsePortRange parses a port range string (e.g. "3389" or "3389-3395") into a list of ports.
func parsePortRange(portRange string) []int {
	parts := strings.SplitN(portRange, "-", 2)
	if len(parts) == 1 {
		p, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err == nil && p > 0 && p <= 65535 {
			return []int{p}
		}
		return nil
	}
	start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
		return nil
	}
	ports := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	return ports
}
