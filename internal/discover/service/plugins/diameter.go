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

type DiameterFingerprinter struct{}

func (DiameterFingerprinter) Name() string        { return "diameter" }
func (DiameterFingerprinter) DefaultPorts() []int { return []int{3868} }

// RFC 6733 sections 3, 4.1 and 5.3 define CER/CEA and their AVP framing.
func (DiameterFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	request := make([]byte, 20)
	request[0], request[4], request[6], request[7] = 1, 0x80, 1, 1
	if _, err = rand.Read(request[12:20]); err != nil {
		return nil, err
	}
	request = append(request, diameterDiscoveryAVP(264, 0x40, []byte("networkscan.invalid"))...)
	request = append(request, diameterDiscoveryAVP(296, 0x40, []byte("invalid"))...)
	local := conn.LocalAddr().(*net.TCPAddr).IP
	address := append([]byte{0, 2}, local.To16()...)
	if v4 := local.To4(); v4 != nil {
		address = append([]byte{0, 1}, v4...)
	}
	request = append(request, diameterDiscoveryAVP(257, 0x40, address)...)
	request = append(request, diameterDiscoveryAVP(266, 0x40, []byte{0, 0, 0, 0})...)
	request = append(request, diameterDiscoveryAVP(269, 0, []byte("networkscan"))...)
	request = append(request, diameterDiscoveryAVP(258, 0x40, []byte{0xff, 0xff, 0xff, 0xff})...)
	request[1], request[2], request[3] = byte(len(request)>>16), byte(len(request)>>8), byte(len(request))
	if _, err = conn.Write(request); err != nil {
		return nil, err
	}
	header := make([]byte, 20)
	if _, err = io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if header[0] != 1 || header[4]&^byte(0x20) != 0 || !bytes.Equal(header[5:12], request[5:12]) || !bytes.Equal(header[12:], request[12:20]) || length < 20 || length > 65536 || length%4 != 0 {
		return nil, fmt.Errorf("invalid Diameter CEA header")
	}
	body := make([]byte, length-20)
	if _, err = io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	metadata, err := diameterDiscoveryMetadata(body)
	if err != nil {
		return nil, err
	}
	metadata["version"] = metadata["firmwareRevision"]
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeDiameter, "DIAMETER", metadata["firmwareRevision"], metadata), nil
}

func diameterDiscoveryAVP(code uint32, flags byte, value []byte) []byte {
	n := 8 + len(value)
	avp := make([]byte, (n+3)&^3)
	binary.BigEndian.PutUint32(avp, code)
	avp[4], avp[5], avp[6], avp[7] = flags, byte(n>>16), byte(n>>8), byte(n)
	copy(avp[8:], value)
	return avp
}

func diameterDiscoveryMetadata(body []byte) (map[string]string, error) {
	metadata := map[string]string{"probe": "capabilities_exchange"}
	for len(body) > 0 {
		if len(body) < 8 {
			return nil, fmt.Errorf("short Diameter AVP")
		}
		code := binary.BigEndian.Uint32(body)
		n := int(body[5])<<16 | int(body[6])<<8 | int(body[7])
		headerLen := 8
		if body[4]&0x80 != 0 {
			headerLen = 12
		}
		padded := (n + 3) &^ 3
		if body[4]&0x1f != 0 || n < headerLen || padded > len(body) {
			return nil, fmt.Errorf("invalid Diameter AVP length/flags")
		}
		value := body[headerLen:n]
		if headerLen == 8 {
			key := ""
			switch code {
			case 264:
				key = "originHost"
			case 296:
				key = "originRealm"
			case 269:
				key = "product"
			case 266:
				key = "vendorID"
			case 267:
				key = "firmwareRevision"
			case 268:
				key = "resultCode"
			}
			if key != "" {
				if _, exists := metadata[key]; exists {
					return nil, fmt.Errorf("duplicate Diameter %s", key)
				}
				if code == 266 || code == 267 || code == 268 {
					if len(value) != 4 {
						return nil, fmt.Errorf("invalid Diameter integer AVP")
					}
					metadata[key] = strconv.FormatUint(uint64(binary.BigEndian.Uint32(value)), 10)
				} else {
					metadata[key] = string(value)
				}
			}
		}
		body = body[padded:]
	}
	result, _ := strconv.Atoi(metadata["resultCode"])
	if result < 1000 || result >= 6000 || metadata["originHost"] == "" || metadata["originRealm"] == "" {
		return nil, fmt.Errorf("missing or invalid Diameter CEA identity/result")
	}
	return metadata, nil
}
