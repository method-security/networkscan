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

type WhoisFingerprinter struct{}

func (WhoisFingerprinter) Name() string { return "whois" }

func (WhoisFingerprinter) DefaultPorts() []int { return []int{43} }

func (WhoisFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte("example.com\r\n"), 4096)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	lower := strings.ToLower(text)
	if strings.Contains(lower, "http/") || (!strings.Contains(lower, "whois") && !strings.Contains(lower, "domain") && !strings.Contains(lower, "registrar") && !strings.HasPrefix(strings.TrimSpace(text), "%")) {
		return nil, fmt.Errorf("not WHOIS")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "WHOIS", "WHOIS", map[string]string{"response": helpers.FirstLine(text)}), nil
}
