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

type RloginFingerprinter struct{}

func (RloginFingerprinter) Name() string { return "rlogin" }

func (RloginFingerprinter) DefaultPorts() []int { return []int{513} }

func (RloginFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte("\x00root\x00root\x00networkscan/9600\x00"), 2048)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "rlogin") && !strings.Contains(lower, "connection refused") && !strings.Contains(lower, "authenticated rlogin") {
		return nil, fmt.Errorf("not rlogin")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeRlogin, "rlogin", "rlogin", map[string]string{"response": helpers.FirstLine(text)}), nil
}
