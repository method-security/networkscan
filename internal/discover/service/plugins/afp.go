package plugins

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type AFPFingerprinter struct{}

func (AFPFingerprinter) Name() string { return "afp" }

func (AFPFingerprinter) DefaultPorts() []int { return []int{548} }

func (AFPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte{0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 4096)
	if err != nil {
		return nil, err
	}
	if len(resp) < 16 || resp[0] != 0x01 || resp[1] != 0x03 || !bytes.Contains(resp, []byte("AFP")) {
		return nil, fmt.Errorf("not AFP")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeAfp, "AFP", "AFP/DSI", map[string]string{"command": "GetStatus"}), nil
}
