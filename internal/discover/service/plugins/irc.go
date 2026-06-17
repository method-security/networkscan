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

type IRCFingerprinter struct{}

func (IRCFingerprinter) Name() string { return "irc" }

func (IRCFingerprinter) DefaultPorts() []int { return []int{6660, 6667, 6697} }

func (IRCFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte("NICK networkscanfp\r\nUSER networkscanfp 0 * :networkscan\r\n"), 4096)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	if !helpers.LooksLikeIRC(text) {
		return nil, fmt.Errorf("not IRC")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeIrc, "IRC", "IRC", map[string]string{"banner": strings.TrimSpace(text)}), nil
}
