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

type SCCPFingerprinter struct{}

func (SCCPFingerprinter) Name() string { return "sccp" }

func (SCCPFingerprinter) DefaultPorts() []int { return []int{2000} }

var sccpServerMessageNames = map[uint32]string{
	0x0081: "RegisterAck",
	0x009b: "CapabilitiesReq",
	0x009d: "RegisterReject",
	0x009f: "Reset",
	0x0100: "KeepAliveAck",
	0x011c: "RegisterTokenReject",
}

func (SCCPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	probe := make([]byte, 12)
	binary.LittleEndian.PutUint32(probe[0:4], 4)
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, probe, 1024)
	if err != nil {
		return nil, err
	}
	if len(resp) < 12 {
		return nil, fmt.Errorf("not SCCP")
	}
	// dataLength counts from the message ID onward, excluding the 8-byte length+reserved header.
	dataLength := binary.LittleEndian.Uint32(resp[0:4])
	reserved := binary.LittleEndian.Uint32(resp[4:8])
	messageID := binary.LittleEndian.Uint32(resp[8:12])
	if dataLength < 4 || dataLength > 2048 || reserved > 0xff {
		return nil, fmt.Errorf("not SCCP")
	}
	if messageID < 0x0081 || messageID > 0x0200 {
		return nil, fmt.Errorf("not SCCP")
	}
	metadata := map[string]string{"message_id": fmt.Sprintf("0x%04x", messageID)}
	if name, ok := sccpServerMessageNames[messageID]; ok {
		metadata["message"] = name
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeSccp, "SCCP", "SCCP", metadata), nil
}
