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

type GitDaemonFingerprinter struct{}

func (GitDaemonFingerprinter) Name() string { return "git-daemon" }

func (GitDaemonFingerprinter) DefaultPorts() []int { return []int{9418} }

func (GitDaemonFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	payload := "git-upload-pack /\x00host=" + host + "\x00"
	probe := []byte(fmt.Sprintf("%04x%s", len(payload)+4, payload))
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, probe, 1024)
	if err != nil {
		return nil, err
	}
	if !helpers.LooksLikeGitDaemon(resp) {
		return nil, fmt.Errorf("not git-daemon")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "Git daemon", "git", map[string]string{"response": strings.TrimSpace(string(resp))}), nil
}
