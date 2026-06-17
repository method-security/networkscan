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

type LPDFingerprinter struct{}

func (LPDFingerprinter) Name() string { return "lpd" }

func (LPDFingerprinter) DefaultPorts() []int { return []int{515} }

func (LPDFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte("\x03networkscan\n"), 2048)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "lpd") && !strings.Contains(lower, "printer") && !strings.Contains(lower, "queue") {
		return nil, fmt.Errorf("not LPD")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeLpd, "Line Printer Daemon", "LPD", map[string]string{"response": helpers.FirstLine(text)}), nil
}
