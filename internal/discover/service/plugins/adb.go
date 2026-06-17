package plugins

import (
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type ADBFingerprinter struct{}

func (ADBFingerprinter) Name() string { return "adb" }

func (ADBFingerprinter) DefaultPorts() []int { return []int{5555} }

func (ADBFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, helpers.ADBCNXNPacket(), 256)
	if err != nil {
		return nil, err
	}
	if len(resp) < 24 {
		return nil, fmt.Errorf("not ADB")
	}
	cmd := string(resp[:4])
	if (cmd != "CNXN" && cmd != "AUTH") || !helpers.ValidADBPacket(resp) {
		return nil, fmt.Errorf("not ADB")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeAdb, "Android Debug Bridge", "ADB", map[string]string{"response_command": cmd}), nil
}
