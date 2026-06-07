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

type DubboFingerprinter struct{}

func (DubboFingerprinter) Name() string { return "dubbo" }

func (DubboFingerprinter) DefaultPorts() []int { return []int{20880} }

func (DubboFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte("ls\r\n"), 4096)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "dubbo>") && !strings.Contains(lower, "dubbo") {
		return nil, fmt.Errorf("not Dubbo")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "Apache Dubbo", "Dubbo", map[string]string{"response": helpers.FirstLine(text)}), nil
}
