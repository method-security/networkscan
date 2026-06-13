// Package nebula implements Nebula overlay network service enumeration.
// It detects Nebula lighthouse presence by sending a crafted handshake
// initiation packet over UDP and observing the response.
package nebula

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	nebulafern "github.com/Method-Security/networkscan/generated/go/enumerate/nebula"
	nebulaprotocol "github.com/Method-Security/networkscan/internal/protocol/nebula"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const (
	// defaultPort is used when a target is supplied without an explicit port.
	defaultPort = nebulaprotocol.DefaultPort
	// readBufSize is the maximum UDP datagram we will accept from a lighthouse.
	readBufSize = 1500
)

// LibraryEnumerateNebula implements the NetworkApplicationLibrary interface for
// Nebula lighthouse detection.
type LibraryEnumerateNebula struct{}

// EnumerateTarget probes a single target (host:port) for Nebula lighthouse presence.
//
// Detection logic:
//  1. Send a 66-byte Nebula handshake initiation (16-byte header + 50 random bytes).
//  2. Read up to 1500 bytes with a deadline derived from the context.
//  3. Set inferredPresent=true if any of the following hold:
//     (a) A RecvError packet is received (lighthouse rejected an invalid handshake),
//     (b) Any valid-version Nebula packet is received (>=16 bytes, version==1),
//     (c) A response of >=16 bytes is successfully parsed.
//  4. On timeout or connection refused: inferredPresent=false, populate error string.
func (l *LibraryEnumerateNebula) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	errors := []string{}
	details := &nebulafern.EnumerateNebulaDetails{}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		// If target has no port, append the default.
		host = target
		portStr = strconv.Itoa(defaultPort)
		target = net.JoinHostPort(host, portStr)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		errMsg := fmt.Sprintf("invalid port in target %q: %v", target, err)
		details.Error = &errMsg
		errors = append(errors, errMsg)
		return &enumeratefern.EnumerateServiceDetails{EnumerateNebulaDetails: details}, errors
	}

	details.Target = host
	details.Port = port

	// Build handshake initiation packet.
	pkt, err := nebulaprotocol.BuildHandshakeInitiation()
	if err != nil {
		errMsg := fmt.Sprintf("failed to build handshake packet: %v", err)
		details.Error = &errMsg
		errors = append(errors, errMsg)
		return &enumeratefern.EnumerateServiceDetails{EnumerateNebulaDetails: details}, errors
	}

	// Derive deadline from context timeout.
	timeout := 5 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		errMsg := fmt.Sprintf("dial %s: %v", addr, err)
		details.Error = &errMsg
		errors = append(errors, errMsg)
		return &enumeratefern.EnumerateServiceDetails{EnumerateNebulaDetails: details}, errors
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(pkt); err != nil {
		errMsg := fmt.Sprintf("write to %s: %v", addr, err)
		details.Error = &errMsg
		errors = append(errors, errMsg)
		return &enumeratefern.EnumerateServiceDetails{EnumerateNebulaDetails: details}, errors
	}

	buf := make([]byte, readBufSize)
	n, err := conn.Read(buf)
	if err != nil {
		// Timeout / no response — not a Nebula lighthouse (or firewalled).
		errMsg := fmt.Sprintf("read from %s: %v", addr, err)
		details.Error = &errMsg
		log.Info("Nebula probe no response",
			svc1log.SafeParam("target", addr),
			svc1log.SafeParam("error", err))
		return &enumeratefern.EnumerateServiceDetails{EnumerateNebulaDetails: details}, errors
	}

	raw := buf[:n]
	rawHex := hex.EncodeToString(raw)
	details.RawResponseHex = &rawHex

	log.Info("Nebula probe response received",
		svc1log.SafeParam("target", addr),
		svc1log.SafeParam("bytes", n))

	// Attempt to parse Nebula header.
	hdr, parseErr := nebulaprotocol.ParseHeader(raw)
	if parseErr == nil {
		// Any valid-version response means a Nebula node is listening.
		details.InferredPresent = true
		details.ParsedHeader = nebulaprotocol.ToFernHeader(hdr)

		if nebulaprotocol.IsRecvError(hdr) {
			log.Info("Nebula RecvError received — lighthouse present",
				svc1log.SafeParam("target", addr))
		} else if nebulaprotocol.IsHandshake(hdr) {
			log.Info("Nebula Handshake response received — lighthouse present",
				svc1log.SafeParam("target", addr))
		} else {
			log.Info("Nebula packet received — lighthouse present",
				svc1log.SafeParam("target", addr),
				svc1log.SafeParam("type", hdr.Type))
		}
	} else if n >= nebulaprotocol.HeaderLen {
		// Got bytes but couldn't parse — conservative: mark present if >=16 bytes received.
		details.InferredPresent = true
		log.Info("Nebula-length response but parse failed",
			svc1log.SafeParam("target", addr),
			svc1log.SafeParam("error", parseErr))
	}

	return &enumeratefern.EnumerateServiceDetails{EnumerateNebulaDetails: details}, errors
}
