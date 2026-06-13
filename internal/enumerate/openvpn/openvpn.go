// Package openvpn implements OpenVPN service enumeration via the control-channel
// handshake probe.
package openvpn

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	openvpnfern "github.com/Method-Security/networkscan/generated/go/enumerate/openvpn"
	openvpnprotocol "github.com/Method-Security/networkscan/internal/protocol/openvpn"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// TODO: CVE-2025-2704 — OpenVPN 2.6.1–2.6.13 DoS when tls-crypt-v2 is enabled.
// Detection requires version + tls-crypt-v2 mode, both extractable from the handshake.
// Waiting on platform support for CVE precondition detection that goes beyond what
// Nuclei HTTP templates can provide (protocol-level signal).

// LibraryEnumerateOpenVPN implements NetworkApplicationLibrary for OpenVPN enumeration.
type LibraryEnumerateOpenVPN struct {
	// Transport specifies whether to probe over UDP or TCP.
	// Defaults to UDP when not set.
	Transport openvpnfern.OpenVpnTransport
}

// EnumerateTarget probes a single target address for an OpenVPN service.
//
// For UDP: sends a 13-byte HARD_RESET_CLIENT_V2 control packet and checks whether
// the server responds with a HARD_RESET_SERVER_V2 that echoes back our session ID.
//
// For TCP: sends the same packet with the 2-byte OpenVPN-over-TCP length prefix.
func (l *LibraryEnumerateOpenVPN) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid target %q: %v", target, err))
		details := &openvpnfern.EnumerateOpenvpnDetails{
			Target:    target,
			Transport: l.transport(),
		}
		return &enumeratefern.EnumerateServiceDetails{EnumerateOpenvpnDetails: details}, errors
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid port in target %q: %v", target, err))
		details := &openvpnfern.EnumerateOpenvpnDetails{
			Target:    host,
			Transport: l.transport(),
		}
		return &enumeratefern.EnumerateServiceDetails{EnumerateOpenvpnDetails: details}, errors
	}

	details := &openvpnfern.EnumerateOpenvpnDetails{
		Target:    host,
		Port:      port,
		Transport: l.transport(),
	}

	transport := l.transport()
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	timeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}

	var isOpenvpn bool
	switch transport {
	case openvpnfern.OpenVpnTransportTcp:
		isOpenvpn, err = probeTCP(ctx, addr, timeout)
	default:
		// Default to UDP
		isOpenvpn, err = probeUDP(ctx, addr, timeout)
	}
	if err != nil {
		log.Warn("OpenVPN probe failed",
			svc1log.SafeParam("target", target),
			svc1log.SafeParam("transport", string(transport)),
			svc1log.SafeParam("error", err))
		errors = append(errors, fmt.Sprintf("probe failed: %v", err))
	}

	details.IsOpenvpn = isOpenvpn
	if isOpenvpn {
		log.Info("OpenVPN detected",
			svc1log.SafeParam("target", target),
			svc1log.SafeParam("transport", string(transport)))
		details.Result = &openvpnfern.OpenVpnEnumerateResult{}
	}

	return &enumeratefern.EnumerateServiceDetails{EnumerateOpenvpnDetails: details}, errors
}

// transport returns the configured transport, defaulting to UDP.
func (l *LibraryEnumerateOpenVPN) transport() openvpnfern.OpenVpnTransport {
	if l.Transport == "" {
		return openvpnfern.OpenVpnTransportUdp
	}
	return l.Transport
}

// probeUDP sends a HARD_RESET_CLIENT_V2 over UDP and returns true when the server
// responds with a HARD_RESET_SERVER_V2 that echoes the client session ID.
func probeUDP(ctx context.Context, addr string, timeout time.Duration) (bool, error) {
	pkt, err := openvpnprotocol.BuildHardResetClientV2()
	if err != nil {
		return false, fmt.Errorf("failed to build probe packet: %w", err)
	}

	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false, fmt.Errorf("dial failed: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	if _, err := conn.Write(pkt); err != nil {
		return false, fmt.Errorf("write failed: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		// No response — not conclusive for UDP (server may silently drop).
		return false, nil
	}
	response := buf[:n]

	// Validate the response: check opcode and session ID echo.
	parsed, err := openvpnprotocol.ParseControlPacket(response)
	if err != nil {
		return false, nil
	}
	if !openvpnprotocol.IsHardResetServer(parsed) {
		return false, nil
	}
	// Extract the client session ID from bytes 1-8 of the probe
	var sessionID [openvpnprotocol.SessionIDLength]byte
	copy(sessionID[:], pkt[1:1+openvpnprotocol.SessionIDLength])
	return openvpnprotocol.ContainsSessionID(response, sessionID), nil
}

// probeTCP sends a length-prefixed HARD_RESET_CLIENT_V2 over TCP and returns true
// when the server responds with a valid OpenVPN server reset message.
func probeTCP(ctx context.Context, addr string, timeout time.Duration) (bool, error) {
	pkt, err := openvpnprotocol.BuildTCPHardResetClientV2()
	if err != nil {
		return false, fmt.Errorf("failed to build TCP probe packet: %w", err)
	}

	var d net.Dialer
	if deadline, ok := ctx.Deadline(); ok {
		d = net.Dialer{Deadline: deadline}
	} else {
		d = net.Dialer{Timeout: timeout}
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, fmt.Errorf("TCP dial failed: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	if _, err := conn.Write(pkt); err != nil {
		return false, fmt.Errorf("TCP write failed: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return false, nil
	}
	response := buf[:n]

	// TCP responses are length-prefixed; strip the 2-byte prefix before parsing.
	if len(response) < 2 {
		return false, nil
	}
	payload := response[2:]

	parsed, err := openvpnprotocol.ParseControlPacket(payload)
	if err != nil {
		return false, nil
	}
	if !openvpnprotocol.IsHardResetServer(parsed) {
		return false, nil
	}
	// Extract client session ID from bytes 3-10 of the framed probe (skip 2-byte len prefix)
	var sessionID [openvpnprotocol.SessionIDLength]byte
	copy(sessionID[:], pkt[3:3+openvpnprotocol.SessionIDLength])
	return openvpnprotocol.ContainsSessionID(payload, sessionID), nil
}
