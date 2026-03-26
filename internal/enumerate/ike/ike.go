package ike

import (
	"context"
	"fmt"
	"net"
	"strconv"

	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	ikefern "github.com/Method-Security/networkscan/generated/go/enumerate/ike"
	ikeprotocol "github.com/Method-Security/networkscan/internal/protocol/ike"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumerateIKE implements NetworkApplicationLibrary for IKE enumeration.
type LibraryEnumerateIKE struct{}

// EnumerateTarget Overview:
// 1. Parse target host:port
// 2. Probe with IKEv2 SA_INIT → detect IKEv2 support, extract SA proposals and vendor IDs
// 3. Probe with IKEv1 Aggressive Mode → detect IKEv1 and Aggressive Mode support
// 4. If target port is not 4500, probe UDP 4500 → detect NAT-T capability
// 5. Analyze vendor IDs for DPD support and vendor identification
// 6. Scan SA proposals for weak algorithms
func (l *LibraryEnumerateIKE) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	var serverInfo commonprotocolfern.IkeServerInfo
	var details ikefern.EnumerateIkeDetails
	errors := []string{}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid target %q: %v", target, err))
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateIkeDetails(&details), errors
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid port in target %q: %v", target, err))
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateIkeDetails(&details), errors
	}
	details.Target = host
	details.Port = port
	// IKEv2 probe
	ikev2Response, err := probeUDP(ctx, target, ikeprotocol.BuildIKEv2SAInitRequest())
	if err != nil {
		log.Warn("IKEv2 probe failed", svc1log.SafeParam("target", target), svc1log.SafeParam("error", err))
	} else if len(ikev2Response) >= 28 && isPlausibleIKEPacket(ikev2Response) {
		applyIKEv2ResponseToServerInfo(ikev2Response, &serverInfo)
		if serverInfo.Ikev2Supported != nil {
			log.Info("IKEv2 response received", svc1log.SafeParam("target", target), svc1log.SafeParam("ikev2", *serverInfo.Ikev2Supported))
		}
	}
	// IKEv1 Aggressive Mode probe
	amResponse, err := probeUDP(ctx, target, buildIKEv1AggressiveModeProbe())
	if err != nil {
		log.Warn("IKEv1 AM probe failed", svc1log.SafeParam("target", target), svc1log.SafeParam("error", err))
	} else if len(amResponse) >= 28 {
		aggressiveMode, ikev1 := isIKEv1AggressiveResponse(amResponse)
		if aggressiveMode {
			serverInfo.AggressiveModeEnabled = &aggressiveMode
		}
		if ikev1 {
			serverInfo.Ikev1Supported = &ikev1
			mergeIKEv1ProposalsIntoServerInfo(ikeprotocol.ParseIKEv1SAResponse(amResponse), &serverInfo)
		}
		log.Info("IKEv1 AM probe response",
			svc1log.SafeParam("target", target),
			svc1log.SafeParam("aggressiveMode", aggressiveMode),
			svc1log.SafeParam("ikev1", ikev1))
	}
	// NAT-T probes on UDP 4500 (only if not already probing 4500).
	// RFC 3948 §2.3 requires a 4-byte Non-ESP marker (0x00000000) before IKE
	// packets on port 4500; without it the receiver treats the initiator SPI
	// bytes as an ESP SPI and silently drops the packet.
	if portStr != "4500" {
		natTarget := net.JoinHostPort(host, "4500")
		// IKEv2 NAT-T probe
		natv2Response, natErr := probeUDP(ctx, natTarget, ikeprotocol.BuildNATTIKEv2SAInitRequest())
		if natErr == nil && len(natv2Response) >= 4 {
			data := stripNonESPMarker(natv2Response)
			if isPlausibleIKEPacket(data) {
				natT := true
				serverInfo.NatTraversalSupported = &natT
				log.Info("NAT-T port 4500 responded to IKEv2", svc1log.SafeParam("host", host), svc1log.SafeParam("responseBytes", len(natv2Response)))
				if serverInfo.Version == nil {
					applyIKEv2ResponseToServerInfo(data, &serverInfo)
				}
			}
		}
		// IKEv1 AM NAT-T probe — some devices only respond to AM on port 4500
		natAMResponse, natAMErr := probeUDP(ctx, natTarget, ikeprotocol.BuildNATTIKEv1AMRequest(buildIKEv1AggressiveModeProbe()))
		if natAMErr == nil && len(natAMResponse) >= 4 {
			// Strip Non-ESP marker (0x00000000) if present per RFC 3948 §2.3.
			// Some implementations omit it, so only strip if the first 4 bytes are zeros.
			data := stripNonESPMarker(natAMResponse)
			if isPlausibleIKEPacket(data) {
				natT := true
				serverInfo.NatTraversalSupported = &natT
				aggressiveMode, ikev1 := isIKEv1AggressiveResponse(data)
				if aggressiveMode {
					serverInfo.AggressiveModeEnabled = &aggressiveMode
				}
				if ikev1 {
					serverInfo.Ikev1Supported = &ikev1
					mergeIKEv1ProposalsIntoServerInfo(ikeprotocol.ParseIKEv1SAResponse(data), &serverInfo)
				}
				log.Info("NAT-T port 4500 responded to IKEv1 AM",
					svc1log.SafeParam("host", host),
					svc1log.SafeParam("aggressiveMode", aggressiveMode))
			}
		}
	}
	// Vendor ID analysis
	if len(serverInfo.VendorIds) > 0 {
		dpd := checkDPDSupport(serverInfo.VendorIds)
		serverInfo.DeadPeerDetectionSupported = &dpd
		serverInfo.VendorIdentification = extractVendorIdentification(serverInfo.VendorIds)
	}
	// Weak algorithm detection
	serverInfo.WeakAlgorithmsDetected = detectWeakAlgorithms(
		serverInfo.EncryptionAlgorithms,
		serverInfo.HashAlgorithms,
		serverInfo.DhGroups,
	)
	details.ServerInfo = &serverInfo
	return enumeratefern.NewEnumerateServiceDetailsFromEnumerateIkeDetails(&details), errors
}
