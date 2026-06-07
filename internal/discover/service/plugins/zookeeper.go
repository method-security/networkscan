package plugins

import (
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type ZooKeeperFingerprinter struct{}

func (ZooKeeperFingerprinter) Name() string { return "zookeeper" }

func (ZooKeeperFingerprinter) DefaultPorts() []int { return []int{2181} }

func (ZooKeeperFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte("ruok"), 16)
	if err != nil {
		return nil, err
	}
	if string(resp) != "imok" {
		return nil, fmt.Errorf("not ZooKeeper")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "ZooKeeper", "ZooKeeper", map[string]string{"four_letter_word": "ruok"}), nil
}
