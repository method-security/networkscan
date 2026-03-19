package ike

import (
	"context"
	"encoding/hex"
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
	} else if len(ikev2Response) >= 28 {
		if header, parseErr := ikeprotocol.ParseIKEHeader(ikev2Response); parseErr == nil {
			ikev2 := header.MajorVersion == 2
			serverInfo.Ikev2Supported = &ikev2
			log.Info("IKEv2 response received", svc1log.SafeParam("target", target), svc1log.SafeParam("ikev2", ikev2))
			version := fmt.Sprintf("IKEv%d", header.MajorVersion)
			initiatorSPI := hex.EncodeToString(header.InitiatorSPI[:])
			responderSPI := hex.EncodeToString(header.ResponderSPI[:])
			exchangeType := ikeprotocol.GetExchangeTypeName(header.ExchangeType)
			flags := fmt.Sprintf("0x%02x", header.Flags)
			messageID := fmt.Sprintf("%d", header.MessageID)
			serverInfo.Version = &version
			serverInfo.InitiatorSpi = &initiatorSPI
			serverInfo.ResponderSpi = &responderSPI
			serverInfo.ExchangeType = &exchangeType
			serverInfo.Flags = &flags
			serverInfo.MessageId = &messageID
			vendorIDs, proposals := ikeprotocol.ParseIKEPayloads(ikev2Response[28:], header.NextPayload)
			serverInfo.VendorIds = vendorIDs
			serverInfo.EncryptionAlgorithms = proposals.EncryptionAlgs
			serverInfo.HashAlgorithms = proposals.HashAlgs
			serverInfo.AuthenticationMethods = proposals.AuthMethods
			serverInfo.DhGroups = proposals.DHGroups
		}
	}
	// IKEv1 Aggressive Mode probe
	amResponse, err := probeUDP(ctx, target, buildIKEv1AggressiveModeProbe())
	if err != nil {
		log.Warn("IKEv1 AM probe failed", svc1log.SafeParam("target", target), svc1log.SafeParam("error", err))
	} else if len(amResponse) >= 28 {
		aggressiveMode, ikev1 := isIKEv1AggressiveResponse(amResponse)
		serverInfo.AggressiveModeEnabled = &aggressiveMode
		serverInfo.Ikev1Supported = &ikev1
		ikev1Proposals := ikeprotocol.ParseIKEv1SAResponse(amResponse)
		for _, a := range ikev1Proposals.EncryptionAlgs {
			serverInfo.EncryptionAlgorithms = ikeprotocol.AppendUnique(serverInfo.EncryptionAlgorithms, a)
		}
		for _, a := range ikev1Proposals.HashAlgs {
			serverInfo.HashAlgorithms = ikeprotocol.AppendUnique(serverInfo.HashAlgorithms, a)
		}
		for _, g := range ikev1Proposals.DHGroups {
			serverInfo.DhGroups = ikeprotocol.AppendUnique(serverInfo.DhGroups, g)
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
		_, natErr := probeUDP(ctx, natTarget, ikeprotocol.BuildNATTIKEv2SAInitRequest())
		if natErr == nil {
			natT := true
			serverInfo.NatTraversalSupported = &natT
			log.Info("NAT-T port 4500 responded to IKEv2", svc1log.SafeParam("host", host))
		}
		// IKEv1 AM NAT-T probe — some devices only respond to AM on port 4500
		natAMResponse, natAMErr := probeUDP(ctx, natTarget, ikeprotocol.BuildNATTIKEv1AMRequest(buildIKEv1AggressiveModeProbe()))
		if natAMErr == nil {
			natT := true
			serverInfo.NatTraversalSupported = &natT
			if len(natAMResponse) >= 28 {
				// Strip Non-ESP marker (0x00000000) if present per RFC 3948 §2.3.
				// Some implementations omit it, so only strip if the first 4 bytes are zeros.
				data := natAMResponse
				if data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0 {
					data = data[4:]
				}
				aggressiveMode, ikev1 := isIKEv1AggressiveResponse(data)
				if aggressiveMode {
					serverInfo.AggressiveModeEnabled = &aggressiveMode
				}
				if ikev1 {
					serverInfo.Ikev1Supported = &ikev1
				}
				ikev1Proposals := ikeprotocol.ParseIKEv1SAResponse(data)
				for _, a := range ikev1Proposals.EncryptionAlgs {
					serverInfo.EncryptionAlgorithms = ikeprotocol.AppendUnique(serverInfo.EncryptionAlgorithms, a)
				}
				for _, a := range ikev1Proposals.HashAlgs {
					serverInfo.HashAlgorithms = ikeprotocol.AppendUnique(serverInfo.HashAlgorithms, a)
				}
				for _, g := range ikev1Proposals.DHGroups {
					serverInfo.DhGroups = ikeprotocol.AppendUnique(serverInfo.DhGroups, g)
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
