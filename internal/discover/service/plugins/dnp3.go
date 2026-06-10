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

type DNP3Fingerprinter struct{}

func (DNP3Fingerprinter) Name() string { return "dnp3" }

func (DNP3Fingerprinter) DefaultPorts() []int { return []int{20000} }

func (DNP3Fingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, buildDNP3LinkStatusRequest(), 292)
	if err != nil {
		return nil, err
	}
	if !validDNP3Frame(resp) {
		return nil, fmt.Errorf("not DNP3")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "DNP3", "DNP3", map[string]string{"response": "link-layer"}), nil
}

func buildDNP3LinkStatusRequest() []byte {
	probe := make([]byte, 0, 101*10)
	for destination := uint16(0); destination <= 100; destination++ {
		frame := []byte{0x05, 0x64, 0x05, 0xc9, 0x00, 0x00, 0x00, 0x00}
		binary.LittleEndian.PutUint16(frame[4:6], destination)
		probe = append(probe, frame...)
		probe = append(probe, dnp3CRC(frame)...)
	}
	return probe
}

func validDNP3Frame(frame []byte) bool {
	if len(frame) < 10 || frame[0] != 0x05 || frame[1] != 0x64 {
		return false
	}
	linkLen := int(frame[2])
	if linkLen < 5 || linkLen > 250 {
		return false
	}
	if len(frame) < 10 || !dnp3CRCOK(frame[:8], frame[8:10]) {
		return false
	}
	controlFunc := frame[3] & 0x0f
	switch controlFunc {
	case 0x00, 0x01, 0x09, 0x0b, 0x0f:
	default:
		return false
	}
	if len(frame) >= 12 {
		dest := binary.LittleEndian.Uint16(frame[4:6])
		src := binary.LittleEndian.Uint16(frame[6:8])
		if dest == 0xffff && src == 0xffff {
			return false
		}
	}
	return true
}

func dnp3CRCOK(data []byte, got []byte) bool {
	if len(got) < 2 {
		return false
	}
	want := dnp3CRC(data)
	return got[0] == want[0] && got[1] == want[1]
}

func dnp3CRC(data []byte) []byte {
	crc := uint16(0)
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&0x0001 != 0 {
				crc = (crc >> 1) ^ 0xa6bc
			} else {
				crc >>= 1
			}
		}
	}
	crc = ^crc
	return []byte{byte(crc & 0xff), byte(crc >> 8)}
}
