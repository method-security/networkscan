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

type HPDataProtectorFingerprinter struct{}

func (HPDataProtectorFingerprinter) Name() string { return "hpdataprotector" }

func (HPDataProtectorFingerprinter) DefaultPorts() []int { return []int{5555, 5556, 12328, 16400} }

func (HPDataProtectorFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	banner, err := helpers.TCPReadBanner(ctx, ip, port, timeout, 1024)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(banner))
	if !looksLikeHPDataProtector(text) {
		return nil, fmt.Errorf("not HP Data Protector")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "HP Data Protector", "OmniInet", map[string]string{"banner": helpers.FirstLine(text)}), nil
}

func looksLikeHPDataProtector(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "data protector") ||
		strings.Contains(lower, "omniback") ||
		strings.Contains(lower, "openview") && strings.Contains(lower, "inet")
}
