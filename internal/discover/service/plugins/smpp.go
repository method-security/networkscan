package plugins

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type SMPPFingerprinter struct{}

func (SMPPFingerprinter) Name() string        { return "smpp" }
func (SMPPFingerprinter) DefaultPorts() []int { return []int{2775, 2776} }

// SMPP 3.4 sections 4.1.3/4.1.4: one bind_receiver with empty credentials.
func (SMPPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	request := make([]byte, 23)
	binary.BigEndian.PutUint32(request, uint32(len(request)))
	binary.BigEndian.PutUint32(request[4:], 1)
	request[19] = 0x34
	if _, err = rand.Read(request[12:16]); err != nil {
		return nil, err
	}
	sequence := binary.BigEndian.Uint32(request[12:]) & 0x7fffffff
	if sequence == 0 {
		sequence = 1
	}
	binary.BigEndian.PutUint32(request[12:], sequence)
	if _, err = conn.Write(request); err != nil {
		return nil, err
	}
	response := make([]byte, 16)
	if _, err = io.ReadFull(conn, response); err != nil {
		return nil, err
	}
	command := binary.BigEndian.Uint32(response[4:])
	status := binary.BigEndian.Uint32(response[8:])
	length := binary.BigEndian.Uint32(response)
	if length < 16 || length > 4096 || binary.BigEndian.Uint32(response[12:]) != sequence || command != 0x80000001 {
		return nil, fmt.Errorf("invalid SMPP length or sequence")
	}
	body := make([]byte, int(length)-16)
	if _, err = io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	metadata := map[string]string{"probe": "bind_receiver", "commandStatus": strconv.FormatUint(uint64(status), 10)}
	if status != 0 {
		switch status {
		case 1, 2, 3, 4, 5, 8, 13, 14, 15, 0x53, 0x54:
		default:
			return nil, fmt.Errorf("unexpected SMPP bind status")
		}
		if len(body) != 0 {
			return nil, fmt.Errorf("unexpected SMPP error body")
		}
	} else {
		end := bytes.IndexByte(body, 0)
		if end < 0 || end >= 16 {
			return nil, fmt.Errorf("invalid SMPP system_id")
		}
		metadata["systemID"] = string(body[:end])
		body = body[end+1:]
		for len(body) > 0 {
			if len(body) < 4 {
				return nil, fmt.Errorf("truncated SMPP TLV")
			}
			tag, n := binary.BigEndian.Uint16(body), int(binary.BigEndian.Uint16(body[2:]))
			body = body[4:]
			if n > len(body) {
				return nil, fmt.Errorf("invalid SMPP TLV length")
			}
			if tag == 0x0210 {
				if n != 1 || metadata["protocolVersion"] != "" {
					return nil, fmt.Errorf("invalid SMPP version TLV")
				}
				switch body[0] {
				case 0x33:
					metadata["protocolVersion"] = "3.3"
				case 0x34:
					metadata["protocolVersion"] = "3.4"
				case 0x50:
					metadata["protocolVersion"] = "5.0"
				default:
					metadata["protocolVersion"] = fmt.Sprintf("0x%02x", body[0])
				}
			}
			body = body[n:]
		}
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeSmpp, "SMPP", metadata["protocolVersion"], metadata), nil
}
