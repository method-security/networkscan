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

type IdentFingerprinter struct{}

func (IdentFingerprinter) Name() string { return "ident" }

func (IdentFingerprinter) DefaultPorts() []int { return []int{113} }

func (IdentFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte("1, 1\r\n"), 256)
	if err != nil {
		return nil, err
	}
	text := strings.ToUpper(string(resp))
	if !strings.Contains(text, "1") || (!strings.Contains(text, " : ERROR : ") && !strings.Contains(text, " : USERID : ")) {
		return nil, fmt.Errorf("not Ident")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeIdent, "Ident", "RFC1413", map[string]string{"response": strings.TrimSpace(string(resp))}), nil
}
