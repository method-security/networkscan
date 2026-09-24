package plugins

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type OpenVPNFingerprinter struct{}

func (OpenVPNFingerprinter) Name() string        { return "OpenVPN" }
func (OpenVPNFingerprinter) DefaultPorts() []int { return []int{1194} }

func (OpenVPNFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	// A key-method-2 reset has opcode 7, a session ID, no ACKs, and packet ID 0.
	request := make([]byte, 14)
	request[0] = 7 << 3
	if _, err := rand.Read(request[1:9]); err != nil {
		return nil, err
	}
	response, err := helpers.UDPExchange(ctx, ip, port, timeout, request, 65535)
	if err != nil {
		return nil, err
	}
	if !validOpenVPNReset(response, request[1:9]) {
		return nil, fmt.Errorf("OpenVPN: invalid reset acknowledgement")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeUdp, common.ProtocolTypeOpenvpn, "openvpn", "", nil), nil
}

// Validate the unauthenticated reliability header described by OpenVPN's network protocol.
// Servers requiring tls-auth or tls-crypt cannot be identified with this probe.
func validOpenVPNReset(packet, session []byte) bool {
	if len(session) != 8 || len(packet) < 10 || packet[0] != 8<<3 {
		return false
	}
	acks := int(packet[9])
	if acks == 0 {
		return len(packet) == 14 && binary.BigEndian.Uint32(packet[10:]) == 0
	}
	remoteOffset := 10 + 4*acks
	if len(packet) != remoteOffset+12 || !bytes.Equal(packet[remoteOffset:remoteOffset+8], session) {
		return false
	}
	acknowledged := false
	for offset := 10; offset < remoteOffset; offset += 4 {
		if binary.BigEndian.Uint32(packet[offset:]) == 0 {
			acknowledged = true
		}
	}
	return acknowledged && binary.BigEndian.Uint32(packet[remoteOffset+8:]) == 0
}
