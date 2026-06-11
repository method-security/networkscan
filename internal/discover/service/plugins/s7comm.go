// Package plugins provides Siemens S7comm / ISO-on-TCP service fingerprinting
// on TCP/102.
//
// This fingerprinter runs inside the parallel service-discovery loop, which
// cancels every probe after a single config-supplied timeout window (default
// 5s). To stay safely inside that budget we do ONLY the minimum to confirm
// COTP/S7comm — a single COTP Connection Request and Connection Confirm.
// The deeper probe (S7 SETUP + SZL reads) is the standalone "discover s7"
// command at internal/discover/s7.
package plugins

import (
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type S7CommFingerprinter struct{}

func (S7CommFingerprinter) Name() string { return "s7comm" }

func (S7CommFingerprinter) DefaultPorts() []int { return []int{102} }

// S7-1500 / S7-1200 modern CPUs — calling TSAP 02.00, called TSAP 03.00.
// This pair is more permissive than the S7-300 default and also gets accepted
// by most S7-300/400 CPUs as long as TSAP filtering isn't enforced.
var s7FingerprintProbe = []byte{
	0x03, 0x00, 0x00, 0x16, // TPKT v3 len 22
	0x11, 0xE0, // COTP CR len 17, code 0xE0
	0x00, 0x00, // dst-ref
	0x00, 0x01, // src-ref
	0x00,             // class 0
	0xC0, 0x01, 0x0A, // TPDU size 1024
	0xC1, 0x02, 0x02, 0x00, // calling TSAP 02 00
	0xC2, 0x02, 0x03, 0x00, // called TSAP 03 00 (rack 0 slot 0)
}

func (S7CommFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.TCPExchange(ctx, ip, port, timeout, s7FingerprintProbe, 256)
	if err != nil {
		return nil, err
	}
	// TPKT(4) header + COTP first byte length + second byte PDU code.
	// CC PDU code is 0xD0; the lower nibble may carry credits.
	if len(resp) < 7 || resp[0] != 0x03 || resp[1] != 0x00 || (resp[5]&0xF0) != 0xD0 {
		return nil, fmt.Errorf("not S7comm")
	}

	// Surface a minimal S7CommServerInfo so consumers can tell apart
	// 'fingerprint only' (everything but cpu/firmware/sn nil) from a
	// 'discover s7' result (rich SZL data). Rack/slot encode the
	// successful called TSAP (rack 0 slot 0 for the modern pair).
	info := &protocol.S7CommServerInfo{
		Rack: intPtr(0),
		Slot: intPtr(0),
	}
	version := "Siemens S7comm"
	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeS7Comm,
		Version:   &version,
		Metadata:  &discoverfern.ServiceMetadata{S7Comm: info},
	}, nil
}

func intPtr(v int) *int { return &v }
