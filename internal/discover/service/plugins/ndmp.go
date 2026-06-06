package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type NDMPFingerprinter struct{}

func (NDMPFingerprinter) Name() string { return "ndmp" }

func (NDMPFingerprinter) DefaultPorts() []int { return []int{10000} }

func (NDMPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, ndmpConnectOpenRequest(), 512)
	if err != nil {
		return nil, err
	}
	if !looksLikeNDMP(resp) {
		return nil, fmt.Errorf("not NDMP")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "NDMP", "NDMP", map[string]string{"response": "connect-open-reply"}), nil
}

func ndmpConnectOpenRequest() []byte {
	packet := make([]byte, 28)
	binary.BigEndian.PutUint32(packet[0:4], 1)
	binary.BigEndian.PutUint32(packet[4:8], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(packet[8:12], 0)
	binary.BigEndian.PutUint32(packet[12:16], 0x900)
	binary.BigEndian.PutUint32(packet[16:20], 0)
	binary.BigEndian.PutUint32(packet[20:24], 0)
	binary.BigEndian.PutUint32(packet[24:28], 4)
	return packet
}

func looksLikeNDMP(resp []byte) bool {
	if len(resp) < 28 {
		return false
	}
	offset := 0
	if resp[0]&0x80 != 0 {
		recordLen := int(binary.BigEndian.Uint32(resp[0:4]) & 0x7fffffff)
		if recordLen <= 0 || recordLen+4 > len(resp) {
			return false
		}
		offset = 4
	}
	if len(resp) < offset+24 {
		return false
	}
	messageType := binary.BigEndian.Uint32(resp[offset+8 : offset+12])
	messageCode := binary.BigEndian.Uint32(resp[offset+12 : offset+16])
	replySequence := binary.BigEndian.Uint32(resp[offset+16 : offset+20])
	if messageType == 0 && messageCode == 0x502 {
		return true
	}
	return messageType == 1 && messageCode == 0x900 && replySequence == 1
}
