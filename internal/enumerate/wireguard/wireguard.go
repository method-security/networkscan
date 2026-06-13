// Package wireguard implements WireGuard "presence inference" enumeration.
//
// WireGuard is silent by design: the server never responds to an unauthenticated
// Handshake Initiation and does not send ICMP port-unreachable messages. This
// asymmetry lets us infer WireGuard presence:
//
//   - Send a 148-byte Handshake Initiation on UDP.
//   - If no ICMP port-unreachable arrives within the timeout AND the UDP send
//     succeeded, classify as INFERRED-WireGuard.
//   - If an unexpected UDP response arrives (another protocol answering), classify
//     as NOT WireGuard.
//
// Note: false positives are possible when any UDP service silently drops traffic
// on a given port.  The inference should be combined with additional signals
// (banner grabbing on TCP 443, etc.) before asserting high-confidence detection.
package wireguard

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	wireguardfern "github.com/Method-Security/networkscan/generated/go/enumerate/wireguard"
	wireguardprotocol "github.com/Method-Security/networkscan/internal/protocol/wireguard"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumerateWireGuard implements NetworkApplicationLibrary for WireGuard
// presence-inference enumeration.
type LibraryEnumerateWireGuard struct{}

// EnumerateTarget sends a WireGuard Handshake Initiation probe to the target
// and infers presence based on the absence of an ICMP port-unreachable response.
func (l *LibraryEnumerateWireGuard) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid target %q: %v", target, err))
		details := &wireguardfern.EnumerateWireguardDetails{
			Target:     target,
			IsInferred: false,
		}
		return &enumeratefern.EnumerateServiceDetails{EnumerateWireguardDetails: details}, errors
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid port in target %q: %v", target, err))
		details := &wireguardfern.EnumerateWireguardDetails{
			Target:     host,
			IsInferred: false,
		}
		return &enumeratefern.EnumerateServiceDetails{EnumerateWireguardDetails: details}, errors
	}

	details := &wireguardfern.EnumerateWireguardDetails{
		Target: host,
		Port:   port,
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	timeout := 5 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}

	isInferred, probeErr := probeWireGuard(ctx, addr, timeout)
	if probeErr != nil {
		log.Warn("WireGuard probe error",
			svc1log.SafeParam("target", target),
			svc1log.SafeParam("error", probeErr))
		errors = append(errors, fmt.Sprintf("probe error: %v", probeErr))
	}

	details.IsInferred = isInferred
	if isInferred {
		log.Info("WireGuard presence inferred",
			svc1log.SafeParam("target", target),
			svc1log.SafeParam("port", port))
	}

	return &enumeratefern.EnumerateServiceDetails{EnumerateWireguardDetails: details}, errors
}

// probeWireGuard sends a WireGuard Handshake Initiation packet to addr and
// returns true (inferred presence) when:
//   - The UDP send succeeds.
//   - No response (UDP datagram) is received within the timeout window.
//
// An ICMP port-unreachable causes the Read to return an error quickly, signalling
// that nothing is listening — returning false. A UDP response from another service
// also returns false.
func probeWireGuard(ctx context.Context, addr string, timeout time.Duration) (bool, error) {
	pkt, err := wireguardprotocol.BuildHandshakeInitiation()
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
		return false, fmt.Errorf("send failed: %w", err)
	}

	// Wait for a response within the timeout.
	buf := make([]byte, 4096)
	_, readErr := conn.Read(buf)
	if readErr != nil {
		// A timeout (deadline exceeded) means no response — infer WireGuard presence.
		if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
			return true, nil
		}
		// An ICMP port-unreachable surfaces as a read error on the connected UDP
		// socket on Linux. This means nothing is listening.
		return false, nil
	}
	// A datagram arrived — some other protocol is responding on this port.
	return false, nil
}
