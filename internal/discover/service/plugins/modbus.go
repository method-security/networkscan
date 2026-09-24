package plugins

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type ModbusFingerprinter struct{}

func (ModbusFingerprinter) Name() string        { return "modbus" }
func (ModbusFingerprinter) DefaultPorts() []int { return []int{502} }

// Modbus application specification 1.1b3 section 6.21: read basic device identification.
func (ModbusFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	request := []byte{0, 0, 0, 0, 0, 5, 1, 0x2b, 0x0e, 1, 0}
	if _, err = rand.Read(request[:2]); err != nil {
		return nil, err
	}
	metadata := map[string]string{"unitID": "1", "probe": "read_device_identification"}
	// Basic identification has only three objects; cap pagination independently of timeouts.
	for page := 0; page < 3; page++ {
		if _, err = conn.Write(request); err != nil {
			return nil, err
		}
		header := make([]byte, 7)
		if _, err = io.ReadFull(conn, header); err != nil {
			return nil, err
		}
		length := int(binary.BigEndian.Uint16(header[4:]))
		if binary.BigEndian.Uint16(header) != binary.BigEndian.Uint16(request) || binary.BigEndian.Uint16(header[2:]) != 0 || header[6] != request[6] || length < 3 || length > 254 {
			return nil, fmt.Errorf("invalid Modbus MBAP header")
		}
		pdu := make([]byte, length-1)
		if _, err = io.ReadFull(conn, pdu); err != nil {
			return nil, err
		}
		if len(pdu) == 2 && pdu[0] == 0xab {
			switch pdu[1] {
			case 1, 2, 3, 4, 5, 6, 8, 10, 11:
				metadata["exceptionCode"] = strconv.Itoa(int(pdu[1]))
				return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeModbus, "MODBUS", "", metadata), nil
			}
			return nil, fmt.Errorf("invalid Modbus exception")
		}
		if len(pdu) < 7 || pdu[0] != 0x2b || pdu[1] != 0x0e || pdu[2] != 1 || (pdu[3]&0x7f < 1 || pdu[3]&0x7f > 3) || (pdu[4] != 0 && pdu[4] != 0xff) || pdu[6] == 0 {
			return nil, fmt.Errorf("invalid Modbus device identification")
		}
		metadata["conformityLevel"] = strconv.Itoa(int(pdu[3]))
		objects := pdu[7:]
		last := int(request[10]) - 1
		for i := 0; i < int(pdu[6]); i++ {
			if len(objects) < 2 || int(objects[0]) <= last || objects[0] > 2 || int(objects[1]) > len(objects)-2 {
				return nil, fmt.Errorf("invalid Modbus object")
			}
			last = int(objects[0])
			n := int(objects[1])
			key := []string{"vendor", "product", "revision"}[last]
			metadata[key] = string(objects[2 : 2+n])
			objects = objects[2+n:]
		}
		if len(objects) != 0 {
			return nil, fmt.Errorf("trailing Modbus object data")
		}
		if pdu[4] == 0 {
			if pdu[5] != 0 {
				return nil, fmt.Errorf("invalid Modbus final object marker")
			}
			return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeModbus, "MODBUS", metadata["revision"], metadata), nil
		}
		if int(pdu[5]) <= last || pdu[5] > 2 {
			return nil, fmt.Errorf("invalid Modbus continuation")
		}
		request[10] = pdu[5]
		binary.BigEndian.PutUint16(request, binary.BigEndian.Uint16(request)+1)
	}
	return nil, fmt.Errorf("too many Modbus pages")
}
