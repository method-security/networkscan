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
	if !isFingerResponse(text, port) {
		return nil, fmt.Errorf("not Finger")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeFinger, "Finger", "RFC1288", map[string]string{"response": helpers.FirstLine(text)}), nil
}

func isFingerResponse(text string, port int) bool {
	lower := strings.ToLower(text)
	if strings.Contains(lower, "http/") {
		return false
	}
	if strings.Contains(lower, "finger") || strings.Contains(lower, "no information") {
		return true
	}
	// A bare login prompt is common across FTP and Telnet. Only accept that
	// weak signal on Finger's well-known port.
	return port == 79 && strings.Contains(lower, "login")
}
