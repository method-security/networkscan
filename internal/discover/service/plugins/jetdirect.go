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

type JetDirectFingerprinter struct{}

func (JetDirectFingerprinter) Name() string { return "jetdirect" }

func (JetDirectFingerprinter) DefaultPorts() []int { return []int{9100} }

func (JetDirectFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	probe := []byte("\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X\r\n")
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, probe, 4096)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	if !strings.Contains(text, "@PJL") && !strings.Contains(strings.ToUpper(text), "INFO ID") {
		return nil, fmt.Errorf("not JetDirect/PJL")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "JetDirect/PJL", "PJL", map[string]string{"response": helpers.FirstLine(text)}), nil
}
