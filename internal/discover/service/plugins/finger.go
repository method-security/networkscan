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

type FingerFingerprinter struct{}

func (FingerFingerprinter) Name() string { return "finger" }

func (FingerFingerprinter) DefaultPorts() []int { return []int{79} }

func (FingerFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte("root\r\n"), 2048)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	lower := strings.ToLower(text)
	if strings.Contains(lower, "http/") || (!strings.Contains(lower, "finger") && !strings.Contains(lower, "login") && !strings.Contains(lower, "no information")) {
		return nil, fmt.Errorf("not Finger")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "Finger", "RFC1288", map[string]string{"response": helpers.FirstLine(text)}), nil
}
