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

type JavaRMIFingerprinter struct{}

func (JavaRMIFingerprinter) Name() string { return "java-rmi" }

func (JavaRMIFingerprinter) DefaultPorts() []int { return []int{1099} }

func (JavaRMIFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte{'J', 'R', 'M', 'I', 0x00, 0x02, 'K'}, 256)
	if err != nil {
		return nil, err
	}
	if len(resp) < 4 || resp[0] != 'N' {
		return nil, fmt.Errorf("not Java RMI")
	}
	hostnameLen := int(binary.BigEndian.Uint16(resp[1:3]))
	if hostnameLen <= 0 || hostnameLen > 255 || len(resp) < 3+hostnameLen+2 || !helpers.IsRMIEndpointHost(resp[3:3+hostnameLen]) {
		return nil, fmt.Errorf("invalid Java RMI endpoint ack")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeJavarmi, "Java RMI", "JRMI", map[string]string{"handshake": "stream-protocol-ack", "endpoint": string(resp[3 : 3+hostnameLen])}), nil
}
