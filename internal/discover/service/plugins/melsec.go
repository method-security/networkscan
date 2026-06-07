package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type MELSECFingerprinter struct{}

func (MELSECFingerprinter) Name() string { return "melsec" }

func (MELSECFingerprinter) DefaultPorts() []int { return []int{5000, 5001, 5006, 5007, 20000} }

func (MELSECFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, melsec3EReadProbe(), 256)
	if err == nil && validMELSEC3EResponse(resp) {
		return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "MELSEC MC", "3E", map[string]string{"frame": "3e-binary"}), nil
	}
	resp, asciiErr := helpers.TCPExchange(ctx, ip, port, timeout, []byte("500000FF03FF000018001004010000D*0000000001"), 256)
	if asciiErr == nil && validMELSEC3EASCIIResponse(resp) {
		return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "MELSEC MC", "3E", map[string]string{"frame": "3e-ascii"}), nil
	}
	if err != nil {
		return nil, err
	}
	if asciiErr != nil {
		return nil, asciiErr
	}
	return nil, fmt.Errorf("not MELSEC MC")
}

func melsec3EReadProbe() []byte {
	return []byte{
		0x50, 0x00, 0x00, 0xff, 0xff, 0x03, 0x00,
		0x0c, 0x00, 0x10, 0x00,
		0x01, 0x04, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xa8,
		0x01, 0x00,
	}
}

func validMELSEC3EResponse(resp []byte) bool {
	if len(resp) < 11 || resp[0] != 0xd0 || resp[1] != 0x00 {
		return false
	}
	if resp[2] != 0x00 || resp[3] != 0xff || resp[4] != 0xff || resp[5] != 0x03 {
		return false
	}
	dataLen := int(binary.LittleEndian.Uint16(resp[7:9]))
	if dataLen < 2 || 9+dataLen > len(resp) {
		return false
	}
	endCode := binary.LittleEndian.Uint16(resp[9:11])
	return endCode == 0x0000 || endCode == 0xc051 || endCode == 0xc052 || endCode == 0xc059 || endCode == 0xc05b
}

func validMELSEC3EASCIIResponse(resp []byte) bool {
	if len(resp) < 22 || string(resp[:4]) != "D000" {
		return false
	}
	if string(resp[4:6]) != "00" || string(resp[6:8]) != "FF" || string(resp[8:12]) != "03FF" {
		return false
	}
	endCode := string(resp[18:22])
	switch endCode {
	case "0000", "C051", "C052", "C059", "C05B":
		return true
	default:
		return false
	}
}
