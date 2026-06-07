package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type AMQPFingerprinter struct{}

func (AMQPFingerprinter) Name() string { return "amqp" }

func (AMQPFingerprinter) DefaultPorts() []int { return []int{5672} }

func (AMQPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}, 4096)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(resp, []byte("AMQP")) {
		return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "AMQP", "AMQP", map[string]string{"response": "protocol-header"}), nil
	}
	if looksLikeAMQPConnectionStart(resp) {
		return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, "AMQP", "0-9-1", map[string]string{"method": "connection.start"}), nil
	}
	return nil, fmt.Errorf("not AMQP")
}

func looksLikeAMQPConnectionStart(resp []byte) bool {
	if len(resp) < 12 || resp[0] != 0x01 || resp[1] != 0x00 {
		return false
	}
	for _, payloadOffset := range []int{7, 6} {
		if payloadOffset == 7 && resp[2] != 0x00 {
			continue
		}
		sizeOffset := payloadOffset - 4
		if sizeOffset < 0 || len(resp) < payloadOffset+5 {
			continue
		}
		size := int(binary.BigEndian.Uint32(resp[sizeOffset:payloadOffset]))
		frameEnd := payloadOffset + size
		if size < 4 || frameEnd >= len(resp) || resp[frameEnd] != 0xce {
			continue
		}
		if binary.BigEndian.Uint16(resp[payloadOffset:payloadOffset+2]) == 10 &&
			binary.BigEndian.Uint16(resp[payloadOffset+2:payloadOffset+4]) == 10 {
			return true
		}
	}
	return false
}
