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

type PoppassdFingerprinter struct{}

func (PoppassdFingerprinter) Name() string { return "poppassd" }

func (PoppassdFingerprinter) DefaultPorts() []int { return []int{106} }

func (PoppassdFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPReadBanner(ctx, ip, port, timeout, 1024)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	lower := strings.ToLower(text)
	if !strings.HasPrefix(text, "200 ") || (!strings.Contains(lower, "poppassd") && !strings.Contains(lower, "who are you")) {
		return nil, fmt.Errorf("not poppassd")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypePoppassd, "poppassd", "poppassd", map[string]string{"banner": strings.TrimSpace(text)}), nil
}
