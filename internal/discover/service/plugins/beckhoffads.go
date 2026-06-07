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

type BeckhoffADSFingerprinter struct{}

func (BeckhoffADSFingerprinter) Name() string { return "beckhoff-ads" }

func (BeckhoffADSFingerprinter) DefaultPorts() []int { return []int{48898} }

func (BeckhoffADSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, beckhoffADSReadDeviceInfoProbe(ip), 512)
	if err != nil {
		return nil, err
	}
	name, ok := parseBeckhoffADSDeviceInfo(resp)
	if !ok {
		return nil, fmt.Errorf("not Beckhoff ADS")
	}
	meta := map[string]string{"command": "read-device-info"}
	if name != "" {
		meta["device"] = name
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "Beckhoff ADS", "ADS", meta), nil
}

func beckhoffADSReadDeviceInfoProbe(ip net.IP) []byte {
	target := append(ip.To4(), 0x01, 0x01)
	if len(target) != 6 {
		target = []byte{0, 0, 0, 0, 1, 1}
	}
	source := []byte{1, 1, 1, 1, 1, 1}
	ams := make([]byte, 32)
	copy(ams[0:6], target)
	binary.LittleEndian.PutUint16(ams[6:8], 10000)
	copy(ams[8:14], source)
	binary.LittleEndian.PutUint16(ams[14:16], 32905)
	binary.LittleEndian.PutUint16(ams[16:18], 0x0001)
	binary.LittleEndian.PutUint16(ams[18:20], 0x0004)
	binary.LittleEndian.PutUint32(ams[20:24], 0)
	binary.LittleEndian.PutUint32(ams[24:28], 0)
	binary.LittleEndian.PutUint32(ams[28:32], 1)
	packet := make([]byte, 6+len(ams))
	binary.LittleEndian.PutUint32(packet[2:6], uint32(len(ams)))
	copy(packet[6:], ams)
	return packet
}

func parseBeckhoffADSDeviceInfo(resp []byte) (string, bool) {
	if len(resp) < 44 {
		return "", false
	}
	amsStart := 0
	if binary.LittleEndian.Uint32(resp[2:6])+6 <= uint32(len(resp)) {
		amsStart = 6
	}
	if len(resp) < amsStart+38 {
		return "", false
	}
	if binary.LittleEndian.Uint16(resp[amsStart+16:amsStart+18]) != 0x0001 {
		return "", false
	}
	if binary.LittleEndian.Uint16(resp[amsStart+18:amsStart+20])&0x0001 == 0 {
		return "", false
	}
	dataLen := int(binary.LittleEndian.Uint32(resp[amsStart+20 : amsStart+24]))
	if dataLen < 24 || amsStart+32+dataLen > len(resp) {
		return "", false
	}
	if binary.LittleEndian.Uint32(resp[amsStart+32:amsStart+36]) != 0 {
		return "", false
	}
	data := resp[amsStart+36 : amsStart+32+dataLen]
	if len(data) < 20 {
		return "", true
	}
	name := strings.TrimRight(string(data[4:]), "\x00")
	if len(name) > 64 {
		name = name[:64]
	}
	return strings.TrimSpace(name), true
}
