// Package plugins provides DNP3 (Distributed Network Protocol 3) UDP service fingerprinting
package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type DNP3UDPFingerprinter struct{}

func (DNP3UDPFingerprinter) Name() string { return "dnp3-udp" }

func (DNP3UDPFingerprinter) DefaultPorts() []int { return []int{20000} }

func (DNP3UDPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.UDPExchange(ctx, ip, port, timeout, buildDNP3LinkStatusRequest(), 292)
	if err != nil {
		return nil, err
	}
	if !validDNP3Frame(resp) {
		return nil, fmt.Errorf("not DNP3")
	}

	// Extract outstation source address from link-layer response.
	// DNP3 frame layout: [0x05][0x64][LEN][CTRL][DEST_LSB][DEST_MSB][SRC_LSB][SRC_MSB][CRC]...
	outstationAddr := binary.LittleEndian.Uint16(resp[6:8])
	sourceAddrStr := strconv.Itoa(int(outstationAddr))

	dnp3Version := "DNP3 L3"
	info := &protocol.Dnp3ServerInfo{
		Version:       &dnp3Version,
		SourceAddress: &sourceAddrStr,
	}

	// Attempt app-layer Read Device Attributes over a new UDP connection
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	attrConn, dialErr := helpers.Dial(ctx, "udp", addr, timeout)
	if dialErr == nil {
		defer func() { _ = attrConn.Close() }()
		readAttrReq := buildDNP3ReadAttributesRequest(outstationAddr, dnp3MasterSourceAddress)
		if _, writeErr := attrConn.Write(readAttrReq); writeErr == nil {
			attrBuf := make([]byte, 1024)
			attrN, readErr := attrConn.Read(attrBuf)
			if readErr == nil && attrN >= 10 {
				parseDeviceAttributes(attrBuf[:attrN], info)
			}
		}
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeDnp3,
		Version:   &dnp3Version,
		Metadata:  &discoverfern.ServiceMetadata{Dnp3: info},
	}

	return result, nil
}
