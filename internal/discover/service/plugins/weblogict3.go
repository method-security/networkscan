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

type WebLogicT3Fingerprinter struct{}

func (WebLogicT3Fingerprinter) Name() string { return "weblogic-t3" }

func (WebLogicT3Fingerprinter) DefaultPorts() []int { return []int{7001, 7002} }

func (WebLogicT3Fingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	probe := []byte("t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n")
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, probe, 512)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	if !strings.HasPrefix(text, "HELO:") || !strings.Contains(text, "\nAS:") {
		return nil, fmt.Errorf("not WebLogic T3")
	}
	version := strings.TrimPrefix(strings.SplitN(text, "\n", 2)[0], "HELO:")
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeWeblogict3, "WebLogic T3", version, map[string]string{"banner": strings.TrimSpace(text)}), nil
}
