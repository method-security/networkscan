package plugins

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"strconv"
	"unicode/utf8"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type STUNFingerprinter struct{}

func (STUNFingerprinter) Name() string        { return "stun" }
func (STUNFingerprinter) DefaultPorts() []int { return []int{3478} }

func (STUNFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request, 1)
	binary.BigEndian.PutUint32(request[4:], 0x2112a442)
	if _, err := rand.Read(request[8:]); err != nil {
		return nil, err
	}
	response, err := helpers.UDPExchange(ctx, ip, port, timeout, request, 65535)
	if err != nil {
		return nil, err
	}
	metadata, err := parseSTUNBindingResponse(response, request[8:])
	if err != nil {
		return nil, err
	}
	metadata["info"] = metadata["software"]
	return helpers.GenericResult(host, ip, port, common.TransportTypeUdp, common.ProtocolTypeStun, "stun", metadata["software"], metadata), nil
}

// RFC 8489 sections 5 and 14 define the header, padded attributes, and fingerprint.
func parseSTUNBindingResponse(packet, transaction []byte) (map[string]string, error) {
	if len(packet) < 20 || len(transaction) != 12 || !bytes.Equal(packet[8:20], transaction) ||
		binary.BigEndian.Uint32(packet[4:8]) != 0x2112a442 {
		return nil, fmt.Errorf("STUN: invalid header or transaction")
	}
	kind := binary.BigEndian.Uint16(packet[:2])
	if kind != 0x0101 && kind != 0x0111 {
		return nil, fmt.Errorf("STUN: not a binding response")
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	if length%4 != 0 || length != len(packet)-20 {
		return nil, fmt.Errorf("STUN: invalid message length")
	}
	metadata := map[string]string{}
	for offset := 20; offset < len(packet); {
		if len(packet)-offset < 4 {
			return nil, fmt.Errorf("STUN: truncated attribute header")
		}
		attribute := binary.BigEndian.Uint16(packet[offset:])
		size := int(binary.BigEndian.Uint16(packet[offset+2:]))
		next := offset + 4 + ((size + 3) &^ 3)
		if next > len(packet) {
			return nil, fmt.Errorf("STUN: truncated attribute value")
		}
		value := packet[offset+4 : offset+4+size]
		switch attribute {
		case 0x8022:
			if !utf8.Valid(value) || utf8.RuneCount(value) > 127 {
				return nil, fmt.Errorf("STUN: invalid software attribute")
			}
			if _, exists := metadata["software"]; !exists {
				metadata["software"] = string(value)
			}
		case 0x0001, 0x0020:
			address, err := stunMappedAddress(value, attribute == 0x0020, packet[4:20])
			if err != nil {
				return nil, err
			}
			key := "mappedAddress"
			if attribute == 0x0020 {
				key = "xorMappedAddress"
			}
			if _, exists := metadata[key]; !exists {
				metadata[key] = address
			}
		case 0x0009:
			if len(value) < 4 || value[2]&7 < 3 || value[2]&7 > 6 || value[3] > 99 || !utf8.Valid(value[4:]) {
				return nil, fmt.Errorf("STUN: invalid error code")
			}
			metadata["errorCode"] = strconv.Itoa(int(value[2]&7)*100 + int(value[3]))
			metadata["errorReason"] = string(value[4:])
		case 0x8028:
			if size != 4 || next != len(packet) || binary.BigEndian.Uint32(value) != crc32.ChecksumIEEE(packet[:offset])^0x5354554e {
				return nil, fmt.Errorf("STUN: invalid fingerprint")
			}
		}
		offset = next
	}
	if kind == 0x0111 && metadata["errorCode"] == "" {
		return nil, fmt.Errorf("STUN: error response without error code")
	}
	return metadata, nil
}

func stunMappedAddress(value []byte, xor bool, mask []byte) (string, error) {
	if len(value) < 4 {
		return "", fmt.Errorf("STUN: truncated address")
	}
	size := 0
	switch value[1] {
	case 1:
		size = 4
	case 2:
		size = 16
	}
	if size == 0 || len(value) != 4+size {
		return "", fmt.Errorf("STUN: invalid address family or length")
	}
	port := binary.BigEndian.Uint16(value[2:4])
	address := append(net.IP(nil), value[4:]...)
	if xor {
		port ^= 0x2112
		for i := range address {
			address[i] ^= mask[i]
		}
	}
	return net.JoinHostPort(address.String(), strconv.Itoa(int(port))), nil
}
