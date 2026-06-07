package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type EthernetIPFingerprinter struct{}

func (EthernetIPFingerprinter) Name() string { return "ethernetip" }

func (EthernetIPFingerprinter) DefaultPorts() []int { return []int{44818} }

func (EthernetIPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, ethernetIPListIdentityRequest(), 1024)
	if err != nil {
		return nil, err
	}
	product, ok := parseEthernetIPIdentity(resp)
	if !ok {
		return nil, fmt.Errorf("not EtherNet/IP")
	}
	lower := strings.ToLower(product)
	if strings.Contains(lower, "unitronics") || strings.Contains(lower, "unistream") {
		return nil, fmt.Errorf("unitronics-specific EtherNet/IP")
	}
	meta := map[string]string{"command": "list-identity"}
	if product != "" {
		meta["identity"] = product
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "EtherNet/IP", "CIP", meta), nil
}

func ethernetIPListIdentityRequest() []byte {
	return []byte{
		0x63, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
}

func parseEthernetIPIdentity(resp []byte) (string, bool) {
	if len(resp) < 30 || binary.LittleEndian.Uint16(resp[0:2]) != 0x0063 {
		return "", false
	}
	length := int(binary.LittleEndian.Uint16(resp[2:4]))
	if length <= 0 || 24+length > len(resp) || binary.LittleEndian.Uint32(resp[8:12]) != 0 {
		return "", false
	}
	itemCount := int(binary.LittleEndian.Uint16(resp[24:26]))
	if itemCount < 1 || itemCount > 4 {
		return "", false
	}
	pos := 26
	for i := 0; i < itemCount && pos+4 <= 24+length; i++ {
		itemType := binary.LittleEndian.Uint16(resp[pos : pos+2])
		itemLen := int(binary.LittleEndian.Uint16(resp[pos+2 : pos+4]))
		pos += 4
		if pos+itemLen > len(resp) {
			return "", false
		}
		if itemType == 0x000c && itemLen >= 15 {
			data := resp[pos : pos+itemLen]
			product := extractStringFromIdentity(data, len(data))
			return product, true
		}
		pos += itemLen
	}
	return "", false
}
