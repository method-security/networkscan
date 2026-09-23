// Package plugins provides IKE (Internet Key Exchange) service fingerprinting
package plugins

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	ikeprotocol "github.com/Method-Security/networkscan/internal/protocol/ike"
)

type IKEFingerprinter struct{}

func (IKEFingerprinter) Name() string { return "ike" }

func (IKEFingerprinter) DefaultPorts() []int { return []int{500, 4500} }

func (IKEFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	conn, err := helpers.Dial(ctx, "udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if err := helpers.SetReadDeadline(conn, timeout); err != nil {
		return nil, err
	}

	request := ikeprotocol.BuildIKEv2SAInitRequest()
	if _, err := rand.Read(request[:8]); err != nil {
		return nil, err
	}
	wireRequest := frameIKERequest(request, port)
	if _, err := conn.Write(wireRequest); err != nil {
		return nil, err
	}

	buffer := make([]byte, 65535)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	response := buffer[:n]
	response, ikeHeader, err := validateIKEReply(response, request, port == 4500)
	if err != nil {
		return nil, err
	}

	vendorIDs, proposals := ikeprotocol.ParseIKEPayloads(response[28:], ikeHeader.NextPayload)

	version := fmt.Sprintf("IKEv%d", ikeHeader.MajorVersion)
	initiatorSPI := hex.EncodeToString(ikeHeader.InitiatorSPI[:])
	responderSPI := hex.EncodeToString(ikeHeader.ResponderSPI[:])
	exchangeType := ikeprotocol.GetExchangeTypeName(ikeHeader.ExchangeType)
	flags := fmt.Sprintf("0x%02x", ikeHeader.Flags)
	messageID := fmt.Sprintf("%d", ikeHeader.MessageID)

	metadata := &protocol.IkeServerInfo{
		Version:      &version,
		InitiatorSpi: &initiatorSPI,
		ResponderSpi: &responderSPI,
		ExchangeType: &exchangeType,
		Flags:        &flags,
		MessageId:    &messageID,
	}

	if len(vendorIDs) > 0 {
		metadata.VendorIds = vendorIDs
	}
	if len(proposals.EncryptionAlgs) > 0 {
		metadata.EncryptionAlgorithms = ikeprotocol.MergeFernEncryptionAlgorithms(metadata.EncryptionAlgorithms, proposals.EncryptionAlgs)
	}
	if len(proposals.HashAlgs) > 0 {
		metadata.HashAlgorithms = ikeprotocol.MergeFernHashAlgorithms(metadata.HashAlgorithms, proposals.HashAlgs)
	}
	if len(proposals.AuthMethods) > 0 {
		metadata.AuthenticationMethods = ikeprotocol.MergeFernAuthenticationMethods(metadata.AuthenticationMethods, proposals.AuthMethods)
	}
	if len(proposals.DHGroups) > 0 {
		metadata.DhGroups = ikeprotocol.MergeFernDHGroups(metadata.DhGroups, proposals.DHGroups)
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeIke,
		Version:   &version,
		Metadata:  &discoverfern.ServiceMetadata{Ike: metadata},
	}

	return result, nil
}

func frameIKERequest(request []byte, port int) []byte {
	if port == 4500 {
		return append(make([]byte, 4), request...)
	}
	return request
}

func validateIKEReply(response, request []byte, natt bool) ([]byte, *ikeprotocol.IKEHeader, error) {
	if natt {
		if len(response) < 4 || binary.BigEndian.Uint32(response[:4]) != 0 {
			return nil, nil, fmt.Errorf("missing IKE non-ESP marker")
		}
		response = response[4:]
	}
	h, err := ikeprotocol.ParseIKEHeader(response)
	if err != nil {
		return nil, nil, err
	}
	if len(request) < 28 || !bytes.Equal(h.InitiatorSPI[:], request[:8]) ||
		h.MajorVersion != 2 || h.MinorVersion != 0 || h.ExchangeType != 34 ||
		h.Flags&0x28 != 0x20 || h.MessageID != binary.BigEndian.Uint32(request[20:24]) ||
		int(h.Length) != len(response) || h.NextPayload == 0 {
		return nil, nil, fmt.Errorf("invalid or uncorrelated IKE response header")
	}
	// The shared metadata parser is intentionally tolerant; validate the entire
	// generic payload chain before passing it any detection evidence.
	offset, next := 28, h.NextPayload
	for next != 0 {
		if len(response)-offset < 4 {
			return nil, nil, fmt.Errorf("truncated IKE payload header")
		}
		length := int(binary.BigEndian.Uint16(response[offset+2 : offset+4]))
		if length < 4 || length > len(response)-offset {
			return nil, nil, fmt.Errorf("invalid IKE payload length")
		}
		if next == 41 && (length < 8 || int(response[offset+5]) > length-8) {
			return nil, nil, fmt.Errorf("invalid IKE notification")
		}
		next = response[offset]
		offset += length
	}
	if offset != len(response) {
		return nil, nil, fmt.Errorf("trailing IKE payload data")
	}
	return response, h, nil
}
