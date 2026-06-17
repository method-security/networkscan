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

type BeanstalkdFingerprinter struct{}

func (BeanstalkdFingerprinter) Name() string { return "beanstalkd" }

func (BeanstalkdFingerprinter) DefaultPorts() []int { return []int{11300} }

func (BeanstalkdFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte("stats\r\n"), 4096)
	if err != nil {
		return nil, err
	}
	text := string(resp)
	if !strings.HasPrefix(text, "OK ") || (!strings.Contains(text, "\npid:") && !strings.Contains(text, "\ncurrent-jobs-urgent:")) {
		return nil, fmt.Errorf("not beanstalkd")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeBeanstalkd, "beanstalkd", "beanstalkd", map[string]string{"response": helpers.FirstLine(text)}), nil
}
