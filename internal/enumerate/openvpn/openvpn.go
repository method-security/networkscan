// Package openvpn implements OpenVPN service enumeration via the control-channel
// handshake probe.
package openvpn

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"time"

	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	openvpnfern "github.com/Method-Security/networkscan/generated/go/enumerate/openvpn"
	openvpnprotocol "github.com/Method-Security/networkscan/internal/protocol/openvpn"
	utils "github.com/Method-Security/networkscan/utils"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// TODO: CVE-2025-2704 — OpenVPN 2.6.1–2.6.13 DoS when tls-crypt-v2 is enabled.
// Detection requires version + tls-crypt-v2 mode, both extractable from the handshake.
// Waiting on platform support for CVE precondition detection that goes beyond what
// Nuclei HTTP templates can provide (protocol-level signal).

// LibraryEnumerateOpenVPN implements NetworkApplicationLibrary for OpenVPN enumeration.
//
// Transport is set by the engine from the validated `--openvpn-transport` CLI flag
// (or the Fern `OpenVpnEnumerateConfig.transport`). The CLI is the single source
// of truth for the default; the library does not re-default an unset value.
//
// TimeoutSeconds, when > 0, overrides the 10-second default per-probe wait (still
// capped by the surrounding context deadline). Sourced from
// `OpenVpnEnumerateConfig.timeout`.
type LibraryEnumerateOpenVPN struct {
	Transport      openvpnfern.OpenVpnTransport
	TimeoutSeconds int
}

// defaultProbeTimeout is the per-target wait used when no override is configured.
const defaultProbeTimeout = 10 * time.Second

// EnumerateTarget probes a single target address for an OpenVPN service.
//
// For UDP: sends a 13-byte HARD_RESET_CLIENT_V2 control packet and checks whether
// the server responds with a HARD_RESET_SERVER_V2 that echoes back our session ID.
//
// For TCP: sends the same packet with the 2-byte OpenVPN-over-TCP length prefix.
func (l *LibraryEnumerateOpenVPN) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	// Transport is set by the engine from the validated CLI default; if it ever
	// reaches the library unset, fall back to UDP so we always produce a defined
	// `transport` value on the details record.
	transport := l.Transport
	if transport == "" {
		transport = openvpnfern.OpenVpnTransportUdp
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid target %q: %v", target, err))
		details := &openvpnfern.EnumerateOpenvpnDetails{
			Target:    target,
			Transport: transport,
		}
		return &enumeratefern.EnumerateServiceDetails{EnumerateOpenvpnDetails: details}, errors
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid port in target %q: %v", target, err))
		details := &openvpnfern.EnumerateOpenvpnDetails{
			Target:    host,
			Transport: transport,
		}
		return &enumeratefern.EnumerateServiceDetails{EnumerateOpenvpnDetails: details}, errors
	}

	details := &openvpnfern.EnumerateOpenvpnDetails{
		Target:    host,
		Port:      port,
		Transport: transport,
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	timeout := defaultProbeTimeout
	if l.TimeoutSeconds > 0 {
		timeout = time.Duration(l.TimeoutSeconds) * time.Second
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}

	var isOpenvpn bool
	var result *openvpnfern.OpenVpnEnumerateResult
	switch transport {
	case openvpnfern.OpenVpnTransportTcp:
		isOpenvpn, result, err = probeTCP(ctx, addr, timeout)
	default:
		isOpenvpn, result, err = probeUDP(ctx, addr, timeout)
	}
	if err != nil {
		netErr := utils.ClassifyNetError(err)
		log.Warn("OpenVPN probe failed",
			svc1log.SafeParam("target", target),
			svc1log.SafeParam("transport", string(transport)),
			svc1log.SafeParam("category", string(netErr.Category)),
			svc1log.SafeParam("error", netErr.Cause))
		errors = append(errors, fmt.Sprintf("probe failed [%s]: %s", netErr.Category, netErr.Cause))
	}

	details.IsOpenvpn = isOpenvpn
	if isOpenvpn {
		log.Info("OpenVPN detected",
			svc1log.SafeParam("target", target),
			svc1log.SafeParam("transport", string(transport)))
		// result may be nil if the probe ack'd but yielded no extractable metadata;
		// keep that distinction so consumers don't synthesize an empty result.
		details.Result = result
	}

	return &enumeratefern.EnumerateServiceDetails{EnumerateOpenvpnDetails: details}, errors
}

// probeUDP sends a HARD_RESET_CLIENT_V2 over UDP and returns
//   - isOpenVPN: true when the server responds with a HARD_RESET_SERVER_V2 that
//     echoes the client session ID
//   - result: a populated OpenVpnEnumerateResult when handshake metadata can be
//     extracted, or nil if the handshake alone yielded no extra metadata
//   - err: transport / send errors (read errors are treated as "no signal", not
//     errors, because OpenVPN servers may legitimately drop unauthenticated UDP)
func probeUDP(ctx context.Context, addr string, timeout time.Duration) (bool, *openvpnfern.OpenVpnEnumerateResult, error) {
	pkt, err := openvpnprotocol.BuildHardResetClientV2()
	if err != nil {
		return false, nil, fmt.Errorf("failed to build probe packet: %w", err)
	}

	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false, nil, fmt.Errorf("dial failed: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// The caller has already capped `timeout` against the context deadline; use it
	// directly so the probe does not wait for the full `--timeout` value when a
	// shorter per-probe cap is in effect.
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(pkt); err != nil {
		return false, nil, fmt.Errorf("write failed: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		// No response — not conclusive for UDP (server may silently drop).
		return false, nil, nil
	}
	response := buf[:n]
	return interpretControlResponse(response, pkt[1:1+openvpnprotocol.SessionIDLength]), buildResult(response), nil
}

// probeTCP sends a length-prefixed HARD_RESET_CLIENT_V2 over TCP and returns the
// same triple as probeUDP. The TCP transport adds a 2-byte big-endian length
// prefix per OpenVPN frame; we slice to that declared length so trailing bytes
// from a coalesced read are not fed into the parser or session-ID scan.
func probeTCP(ctx context.Context, addr string, timeout time.Duration) (bool, *openvpnfern.OpenVpnEnumerateResult, error) {
	pkt, err := openvpnprotocol.BuildTCPHardResetClientV2()
	if err != nil {
		return false, nil, fmt.Errorf("failed to build TCP probe packet: %w", err)
	}

	// Use the capped probe timeout, not the raw context deadline, so the per-probe
	// budget (default 10s, or the configured openvpnConfig.timeout) is honored even
	// when `--timeout 30` widens the context window.
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, nil, fmt.Errorf("TCP dial failed: %w", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(pkt); err != nil {
		return false, nil, fmt.Errorf("TCP write failed: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return false, nil, nil
	}
	response := buf[:n]

	// TCP frames carry a 2-byte big-endian length prefix; slice to the declared
	// length so a single read that picks up more than one frame (or a stray byte
	// after the first frame) doesn't skew opcode/session-ID validation.
	if len(response) < 2 {
		return false, nil, nil
	}
	declared := int(binary.BigEndian.Uint16(response[0:2]))
	if declared <= 0 || 2+declared > len(response) {
		return false, nil, nil
	}
	payload := response[2 : 2+declared]
	// The framed probe places its session ID at offset 3 (after the 2-byte length
	// prefix and 1-byte opcode), so the client session bytes are pkt[3:3+8].
	return interpretControlResponse(payload, pkt[3:3+openvpnprotocol.SessionIDLength]), buildResult(payload), nil
}

// interpretControlResponse parses the (de-framed) bytes and returns true only
// when the opcode is HARD_RESET_SERVER_V2 and the echoed client session ID is
// present. clientSession is the 8 raw session-ID bytes from the probe packet.
func interpretControlResponse(payload []byte, clientSession []byte) bool {
	parsed, err := openvpnprotocol.ParseControlPacket(payload)
	if err != nil {
		return false
	}
	if !openvpnprotocol.IsHardResetServer(parsed) {
		return false
	}
	var sessionID [openvpnprotocol.SessionIDLength]byte
	copy(sessionID[:], clientSession)
	return openvpnprotocol.ContainsSessionID(payload, sessionID)
}

// buildResult extracts what the HARD_RESET_SERVER_V2 handshake actually exposes
// about the OpenVPN deployment. The unauthenticated handshake reveals very little
// beyond presence: version, cipher, and TLS protocol version live inside the
// (TLS-protected) control channel after key negotiation, and tls-auth-mode
// detection requires sending HMAC'd probes. Until we extend the probe to do
// that, we return nil so consumers don't synthesize an empty OpenVpnEnumerateResult
// — the Result field is `optional` for exactly this reason.
//
// See the CVE-2025-2704 TODO above; the same upstream work that unlocks
// tls-crypt-v2 mode detection will also produce the metadata fields here.
func buildResult(_ []byte) *openvpnfern.OpenVpnEnumerateResult {
	return nil
}
