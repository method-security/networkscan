package plugins

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type SAPRouterFingerprinter struct{}

func (SAPRouterFingerprinter) Name() string { return "saprouter" }

func (SAPRouterFingerprinter) DefaultPorts() []int { return []int{3299} }

func (SAPRouterFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte{0x00, 0x00, 0x00, 0x00}, 512)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(resp))
	if !strings.Contains(strings.ToLower(text), "saprouter") {
		return nil, fmt.Errorf("not SAProuter")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeSaprouter, "SAProuter", "SAP NI", map[string]string{"response": helpers.FirstLine(text)}), nil
}
