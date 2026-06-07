package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type JMXFingerprinter struct{}

func (JMXFingerprinter) Name() string { return "jmx" }

func (JMXFingerprinter) DefaultPorts() []int {
	return []int{1099, 7676, 8686, 9010, 9011, 9076, 9119, 9611, 9999, 7199, 7091}
}

func (JMXFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, jmxRegistryListCall(), 16384)
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(bytes.ToLower(resp), []byte("jmxrmi")) {
		return nil, fmt.Errorf("not JMX")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "JMX", "JMX RMI", map[string]string{"rmi_registry_binding": "jmxrmi"}), nil
}

func jmxRegistryListCall() []byte {
	packet := make([]byte, 0, 48)
	packet = append(packet, 'J', 'R', 'M', 'I', 0x00, 0x02, 0x4c, 0x50)
	packet = append(packet, 0xac, 0xed, 0x00, 0x05, 0x77, 0x22)
	packet = binary.BigEndian.AppendUint64(packet, 0)
	packet = binary.BigEndian.AppendUint32(packet, 0)
	packet = binary.BigEndian.AppendUint64(packet, 0)
	packet = binary.BigEndian.AppendUint16(packet, 0)
	packet = binary.BigEndian.AppendUint32(packet, 1)
	packet = binary.BigEndian.AppendUint64(packet, 0x44154dc9d4e63bdf)
	return packet
}
