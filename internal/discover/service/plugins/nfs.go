package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type NFSFingerprinter struct{}

func (NFSFingerprinter) Name() string { return "nfs" }

func (NFSFingerprinter) DefaultPorts() []int { return []int{2049} }

func (NFSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	for _, version := range []uint32{3, 4} {
		resp, err := helpers.TCPExchange(ctx, ip, port, timeout, nfsTCPNullCall(version), 1024)
		if err != nil {
			continue
		}
		if ok, status := validNFSRPCReply(resp); ok {
			return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeNfs, "NFS", fmt.Sprintf("NFSv%d", version), map[string]string{"rpc_status": status}), nil
		}
	}
	return nil, fmt.Errorf("not NFS")
}

func nfsTCPNullCall(version uint32) []byte {
	call := nfsRPCNullCall(version)
	out := make([]byte, 4+len(call))
	binary.BigEndian.PutUint32(out[0:4], 0x80000000|uint32(len(call)))
	copy(out[4:], call)
	return out
}

func nfsRPCNullCall(version uint32) []byte {
	packet := make([]byte, 40)
	binary.BigEndian.PutUint32(packet[0:4], 0x4e465330)
	binary.BigEndian.PutUint32(packet[4:8], 0)
	binary.BigEndian.PutUint32(packet[8:12], 2)
	binary.BigEndian.PutUint32(packet[12:16], 100003)
	binary.BigEndian.PutUint32(packet[16:20], version)
	binary.BigEndian.PutUint32(packet[20:24], 0)
	binary.BigEndian.PutUint32(packet[24:28], 0)
	binary.BigEndian.PutUint32(packet[28:32], 0)
	binary.BigEndian.PutUint32(packet[32:36], 0)
	binary.BigEndian.PutUint32(packet[36:40], 0)
	return packet
}

func validNFSRPCReply(resp []byte) (bool, string) {
	if len(resp) >= 4 && resp[0]&0x80 != 0 {
		recordLen := int(binary.BigEndian.Uint32(resp[0:4]) & 0x7fffffff)
		if recordLen <= 0 || recordLen+4 > len(resp) {
			return false, ""
		}
		resp = resp[4 : 4+recordLen]
	}
	if len(resp) < 24 || binary.BigEndian.Uint32(resp[0:4]) != 0x4e465330 {
		return false, ""
	}
	if binary.BigEndian.Uint32(resp[4:8]) != 1 || binary.BigEndian.Uint32(resp[8:12]) != 0 {
		return false, ""
	}
	verifierLen := int(binary.BigEndian.Uint32(resp[16:20]))
	if verifierLen > 400 || len(resp) < 20+verifierLen {
		return false, ""
	}
	offset := 20 + ((verifierLen + 3) &^ 3)
	if len(resp) < offset+4 {
		return false, ""
	}
	acceptStat := binary.BigEndian.Uint32(resp[offset : offset+4])
	switch acceptStat {
	case 0:
		return true, "rpc-accepted"
	case 2:
		if len(resp) >= offset+12 {
			return true, "nfs-program-version-mismatch"
		}
	}
	return false, ""
}
