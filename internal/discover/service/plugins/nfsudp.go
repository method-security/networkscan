package plugins

import (
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type NFSUDPFingerprinter struct{}

func (NFSUDPFingerprinter) Name() string { return "nfs-udp" }

func (NFSUDPFingerprinter) DefaultPorts() []int { return []int{2049} }

func (NFSUDPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	for _, version := range []uint32{3, 4} {
		resp, err := helpers.UDPExchange(ctx, ip, port, timeout, nfsRPCNullCall(version), 1024)
		if err != nil {
			continue
		}
		if ok, status := validNFSRPCReply(resp); ok {
			return helpers.GenericResult(host, ip, port, common.TransportTypeUdp, "NFS", fmt.Sprintf("NFSv%d", version), map[string]string{"rpc_status": status}), nil
		}
	}
	return nil, fmt.Errorf("not NFS")
}
