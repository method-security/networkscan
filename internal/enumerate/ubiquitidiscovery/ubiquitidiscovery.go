// Package ubiquitidiscovery provides Ubiquiti Discovery Protocol (UDP/10001)
// enumeration.
//
// Ubiquiti devices across AirOS, AirMAX, UniFi, and EdgeOS firmware families
// respond to a single 4-byte UDP discovery packet with a TLV-encoded reply
// containing model, firmware, MAC, IP, hostname, uptime, and (on wireless)
// ESSID — all pre-auth and unauthenticated.  The protocol is documented by
// Ubiquiti directly (https://help.ui.com/hc/en-us/articles/204976244) and
// reverse-engineered in community Python implementations.
//
// AITF-125 hard rules:
//   - NO credential brute force
//   - NO authentication bypass / RCE attempt
//   - NO state mutation
//
// Strictly read-only — send one packet, parse the response, close the socket.
package ubiquitidiscovery

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	commonProtocol "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	udFern "github.com/Method-Security/networkscan/generated/go/enumerate/ubiquitidiscovery"
	"github.com/Method-Security/networkscan/utils"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumerateUbiquitiDiscovery implements NetworkApplicationLibrary for
// the Ubiquiti Discovery Protocol.
type LibraryEnumerateUbiquitiDiscovery struct{}

// EnumerateTarget probes UDP/10001 with the v1 Discovery request and parses
// the TLV-encoded response.  Falls back to the v2 request shape when v1 elicits
// no response — modern UniFi firmware sometimes only honours v2.
func (l *LibraryEnumerateUbiquitiDiscovery) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Ubiquiti Discovery enumeration", svc1log.SafeParam("target", target))

	details := udFern.EnumerateUbiquitiDiscoveryDetails{Target: target}
	var errors []string

	host, port := utils.ParseHostPort(target, defaultUbiquitiDiscoveryPort)
	if host == "" {
		errors = append(errors, fmt.Sprintf("invalid target %q: could not parse host:port", target))
		return &enumeratefern.EnumerateServiceDetails{EnumerateUbiquitiDiscoveryDetails: &details}, errors
	}
	addr := utils.FormatHostPort(host, port)
	details.Target = addr

	if err := ctx.Err(); err != nil {
		errors = append(errors, fmt.Sprintf("context expired before probe started: %v", err))
		return &enumeratefern.EnumerateServiceDetails{EnumerateUbiquitiDiscoveryDetails: &details}, errors
	}

	timeout := time.Duration(defaultUbiquitiDiscoveryTimeoutMs) * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}

	// Each variant gets half the budget so both can run end-to-end without
	// the second variant starving when v1 takes the long way around.
	// Only apply the 1-second floor when the total budget can support both
	// variants at that minimum; otherwise use timeout/2 as-is.
	perVariantTimeout := timeout / 2
	if perVariantTimeout < time.Second && timeout >= 2*time.Second {
		perVariantTimeout = time.Second
	}

	// Try v1 first (most common across AirOS / AirMAX / older UniFi).
	respBytes, variant, err := probeDiscovery(ctx, addr, perVariantTimeout)
	if err != nil {
		// v1 failed — surface the failure as a portOpen=false hint, but try v2
		// before giving up (some UniFi firmware refuses v1 outright).
		log.Info("Ubiquiti Discovery v1 probe failed; trying v2",
			svc1log.SafeParam("error", err.Error()))
		v2Resp, v2Variant, v2Err := probeDiscoveryV2(ctx, addr, perVariantTimeout)
		if v2Err != nil {
			portOpen := false
			details.PortOpen = &portOpen
			errors = append(errors, fmt.Sprintf("UDP probe failed (v1: %v; v2: %v)", err, v2Err))
			return &enumeratefern.EnumerateServiceDetails{EnumerateUbiquitiDiscoveryDetails: &details}, errors
		}
		respBytes = v2Resp
		variant = v2Variant
	}

	portOpen := true
	details.PortOpen = &portOpen

	raw := hex.EncodeToString(respBytes)
	details.RawResponse = &raw

	version, records, parseErr := parseDiscoveryResponse(respBytes)
	if parseErr != nil {
		// Surface the raw bytes for triage even when TLV parsing fails — the
		// peer responded on UDP/10001 but doesn't speak stock Discovery.
		log.Info("Ubiquiti Discovery TLV parse failed",
			svc1log.SafeParam("variant", variant),
			svc1log.SafeParam("error", parseErr.Error()))
		errors = append(errors, fmt.Sprintf("Discovery TLV parse failed (variant %s): %v", variant, parseErr))
		return &enumeratefern.EnumerateServiceDetails{EnumerateUbiquitiDiscoveryDetails: &details}, errors
	}

	fp := extractFingerprint(records)
	si := commonProtocol.UbiquitiDiscoveryServerInfo{}
	if version != 0 {
		v := int(version)
		si.ProtocolVersion = &v
	}
	if fp.MAC != "" {
		v := strings.ToUpper(fp.MAC)
		si.MacAddress = &v
	}
	if fp.IPAddress != "" {
		si.ReportedIpAddress = &fp.IPAddress
	}
	if fp.Model != "" {
		si.DeviceModel = &fp.Model
	}
	if fp.Firmware != "" {
		si.FirmwareVersion = &fp.Firmware
	}
	if fp.Hostname != "" {
		si.Hostname = &fp.Hostname
	}
	if fp.Platform != "" {
		si.Platform = &fp.Platform
	}
	if fp.Essid != "" {
		si.Essid = &fp.Essid
	}
	if fp.UptimeSecs != nil {
		v := int(*fp.UptimeSecs)
		si.UptimeSeconds = &v
	}
	if fp.RecordCount > 0 {
		v := fp.RecordCount
		si.TlvRecordCount = &v
	}

	details.ServerInfo = &si

	log.Info("Ubiquiti Discovery probe succeeded",
		svc1log.SafeParam("target", addr),
		svc1log.SafeParam("variant", variant),
		svc1log.SafeParam("model", fp.Model),
		svc1log.SafeParam("records", fp.RecordCount))

	return &enumeratefern.EnumerateServiceDetails{EnumerateUbiquitiDiscoveryDetails: &details}, errors
}

// probeDiscovery sends the v1 Discovery request and reads one UDP response.
func probeDiscovery(ctx context.Context, addr string, timeout time.Duration) ([]byte, string, error) {
	resp, err := sendUDP(ctx, addr, discoveryRequestV1, timeout)
	return resp, "v1", err
}

// probeDiscoveryV2 sends the v2 Discovery request and reads one UDP response.
func probeDiscoveryV2(ctx context.Context, addr string, timeout time.Duration) ([]byte, string, error) {
	resp, err := sendUDP(ctx, addr, discoveryRequestV2, timeout)
	return resp, "v2", err
}

// sendUDP dials the UDP endpoint, writes the request packet, and reads one
// response capped at discoveryResponseBodyCap.  Closes the socket on every exit
// path.  Mirrors the IKE precedent (`internal/enumerate/ike/helpers.go`).
func sendUDP(ctx context.Context, addr string, packet []byte, timeout time.Duration) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	buf := make([]byte, discoveryResponseBodyCap)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
