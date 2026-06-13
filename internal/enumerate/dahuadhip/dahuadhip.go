// Package dahuadhip provides Dahua DHIP (Dahua HTTP-like Protocol) service enumeration.
//
// DHIP is the proprietary control-plane protocol Dahua surveillance devices expose
// on TCP/37777 — advertised in the device's HTTP /cap.js as `capTcpPort` per the
// SEC-702 TC-002/005/008/010/014 corpus.  Pre-auth single-packet fingerprint;
// strictly read-only.
//
// The probe sends one DHIP-framed `global.login` JSON-RPC request with empty
// credentials and parses the error response for:
//
//   - encryptionMode ("Default", "OldDigest", "Basic")
//   - authenticationRealm (plaintext serial on 2017-era firmware, hex hash on 2019+)
//   - whether the realm format looks like a plaintext Dahua serial number
//   - JSON-RPC id / session / error-code echoes
//
// AITF-125 hard rules (carried forward from SEC-702):
//   - NO credential brute force
//   - NO authentication bypass (CVE-2021-33044 / CVE-2021-33045 are out of scope)
//   - NO state mutation
//
// References for the wire protocol:
//   - https://github.com/mcw0/DahuaConsole (Python, MIT)
//   - https://github.com/At-Hac/python-dahua-rpc
package dahuadhip

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	commonProtocol "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	dhipFern "github.com/Method-Security/networkscan/generated/go/enumerate/dahuadhip"
	"github.com/Method-Security/networkscan/utils"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumerateDahuaDhip implements NetworkApplicationLibrary for Dahua DHIP enumeration.
type LibraryEnumerateDahuaDhip struct{}

// EnumerateTarget connects to a DHIP endpoint, sends a single read-only global.login
// JSON-RPC probe, and parses the device's fingerprint disclosure.
func (l *LibraryEnumerateDahuaDhip) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Dahua DHIP enumeration", svc1log.SafeParam("target", target))

	details := dhipFern.EnumerateDahuaDhipDetails{Target: target}
	var errors []string

	host, port := utils.ParseHostPort(target, defaultDahuaDhipPort)
	if host == "" {
		errors = append(errors, fmt.Sprintf("invalid target %q: could not parse host:port", target))
		return &enumeratefern.EnumerateServiceDetails{EnumerateDahuaDhipDetails: &details}, errors
	}
	addr := utils.FormatHostPort(host, port)
	details.Target = addr

	if err := ctx.Err(); err != nil {
		errors = append(errors, fmt.Sprintf("context expired before probe started: %v", err))
		return &enumeratefern.EnumerateServiceDetails{EnumerateDahuaDhipDetails: &details}, errors
	}

	timeout := time.Duration(defaultDahuaDhipTimeoutMs) * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}

	// Step 1: TCP reachability.  Use a third of the total budget for the
	// initial dial so a slow handshake cannot starve the read.
	dialTimeout := timeout / 3
	if dialTimeout < time.Second {
		dialTimeout = time.Second
	}
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		portOpen := false
		details.PortOpen = &portOpen
		errors = append(errors, fmt.Sprintf("TCP connection failed: %v", err))
		return &enumeratefern.EnumerateServiceDetails{EnumerateDahuaDhipDetails: &details}, errors
	}
	defer func() { _ = conn.Close() }()

	portOpen := true
	details.PortOpen = &portOpen

	// Step 2: Send the DHIP-framed global.login probe.
	frame := buildDhipFrame([]byte(dhipLoginProbeBody), 0)
	writeDeadline := time.Now().Add(timeout)
	if err := conn.SetWriteDeadline(writeDeadline); err != nil {
		errors = append(errors, fmt.Sprintf("set write deadline: %v", err))
		return &enumeratefern.EnumerateServiceDetails{EnumerateDahuaDhipDetails: &details}, errors
	}
	if _, err := conn.Write(frame); err != nil {
		errors = append(errors, fmt.Sprintf("write DHIP probe: %v", err))
		return &enumeratefern.EnumerateServiceDetails{EnumerateDahuaDhipDetails: &details}, errors
	}

	// Step 3: Read the 32-byte response header.
	readDeadline := time.Now().Add(timeout)
	if err := conn.SetReadDeadline(readDeadline); err != nil {
		errors = append(errors, fmt.Sprintf("set read deadline: %v", err))
		return &enumeratefern.EnumerateServiceDetails{EnumerateDahuaDhipDetails: &details}, errors
	}

	headerBuf := make([]byte, dhipHeaderLen)
	n, err := io.ReadFull(conn, headerBuf)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			errors = append(errors, fmt.Sprintf("peer closed before DHIP header received (%d bytes)", n))
		} else {
			errors = append(errors, fmt.Sprintf("read DHIP header: %v", err))
		}
		return &enumeratefern.EnumerateServiceDetails{EnumerateDahuaDhipDetails: &details}, errors
	}

	// Validate header framing — does the listener speak DHIP at all?
	declaredLen, parseErr := validateDhipHeader(headerBuf)
	if parseErr != nil {
		extraBuf := make([]byte, 256)
		extraN, _ := conn.Read(extraBuf)
		raw := hex.EncodeToString(headerBuf)
		if extraN > 0 {
			raw += " | extra: " + hex.EncodeToString(extraBuf[:extraN])
		}
		details.RawResponse = &raw
		errors = append(errors, fmt.Sprintf("DHIP framing failed: %v", parseErr))
		return &enumeratefern.EnumerateServiceDetails{EnumerateDahuaDhipDetails: &details}, errors
	}

	// Read the JSON-RPC body using the declared length from the validated header.
	bodyBytes := make([]byte, declaredLen)
	if _, err := io.ReadFull(conn, bodyBytes); err != nil {
		errors = append(errors, fmt.Sprintf("read DHIP body: %v", err))
		// Header framing succeeded — surface that as a positive DHIP signal
		// even though the body read failed.
		raw := hex.EncodeToString(headerBuf)
		details.RawResponse = &raw
		requiresAuth := true
		details.RequiresAuth = &requiresAuth
		return &enumeratefern.EnumerateServiceDetails{EnumerateDahuaDhipDetails: &details}, errors
	}

	rawBody := strings.TrimSpace(string(bodyBytes))
	details.RawResponse = &rawBody

	// DHIP framing OK — auth is structurally required (we sent empty creds).
	requiresAuth := true
	details.RequiresAuth = &requiresAuth

	// Step 4: Parse the JSON-RPC body for fingerprint fields.
	resp, parseErr := parseLoginResponse(bodyBytes)
	if parseErr != nil {
		log.Info("DHIP body parse failed (framing OK, body non-JSON)",
			svc1log.SafeParam("target", addr),
			svc1log.SafeParam("error", parseErr.Error()))
		return &enumeratefern.EnumerateServiceDetails{EnumerateDahuaDhipDetails: &details}, errors
	}

	si := serverInfoFromResponse(resp)
	details.ServerInfo = &si

	encMode := ""
	if si.EncryptionMode != nil {
		encMode = *si.EncryptionMode
	}
	log.Info("DHIP probe succeeded",
		svc1log.SafeParam("target", addr),
		svc1log.SafeParam("encryption", encMode),
		svc1log.SafeParam("realm_present", si.AuthenticationRealm != nil))

	return &enumeratefern.EnumerateServiceDetails{EnumerateDahuaDhipDetails: &details}, errors
}

// serverInfoFromResponse extracts fingerprint fields out of the parsed JSON-RPC
// reply into the Fern protocol struct.  Only sets fields that are present and
// non-empty so that the absence of a field stays distinguishable from an
// explicit empty value downstream.
func serverInfoFromResponse(resp *dhipLoginResponse) commonProtocol.DahuaDhipServerInfo {
	si := commonProtocol.DahuaDhipServerInfo{}
	if resp == nil {
		return si
	}
	if resp.ID != nil {
		v := *resp.ID
		si.JsonRpcId = &v
	}
	if resp.Session != nil {
		// Truncate to int — Dahua firmware reports 32-bit session ids in practice;
		// the wider int64 in the JSON decoder is just a safety hedge against
		// firmware reporting >2^31.
		v := int(*resp.Session)
		si.JsonRpcSessionId = &v
	}
	if resp.Error != nil && resp.Error.Code != nil {
		v := *resp.Error.Code
		si.JsonRpcErrorCode = &v
	}
	if resp.Params != nil {
		if resp.Params.Encryption != nil && *resp.Params.Encryption != "" {
			v := *resp.Params.Encryption
			si.EncryptionMode = &v
		}
		if resp.Params.Realm != nil && *resp.Params.Realm != "" {
			v := *resp.Params.Realm
			si.AuthenticationRealm = &v
			looksPlain := realmLooksLikePlainSerial(v)
			si.RealmLooksLikePlainSerial = &looksPlain
		}
	}
	return si
}
