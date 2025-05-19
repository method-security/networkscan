package grpc

import (
	"bytes"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

/* ---------- public plugin objects ---------- */

type GRPCMetadata struct {
	PrefaceAck         bool   `json:"prefaceAck"`
	SupportsReflection bool   `json:"supportsReflection,omitempty"`
	HealthStatus       string `json:"healthStatus,omitempty"`
}

func (GRPCMetadata) Type() string { return "grpc" } // satisfies plugins.Metadata

type GRPCPlugin struct{}
type GRPCTLSPlugin struct{}

const (
	GRPC    = "grpc"
	GRPCTLS = "grpc" // same logical service, different transport
)

func init() {
	plugins.RegisterPlugin(&GRPCPlugin{})
	plugins.RegisterPlugin(&GRPCTLSPlugin{})
}

/* ---------- interface glue ---------- */

func (p *GRPCPlugin) Name() string    { return GRPC }
func (p *GRPCTLSPlugin) Name() string { return GRPCTLS }

func (p *GRPCPlugin) Type() plugins.Protocol    { return plugins.TCP }
func (p *GRPCTLSPlugin) Type() plugins.Protocol { return plugins.TCPTLS }

// gRPC default ports + popular fall-backs
func (p *GRPCPlugin) PortPriority(port uint16) bool {
	return port == 50051 || port == 6565
}
func (p *GRPCTLSPlugin) PortPriority(port uint16) bool {
	return port == 443 || port == 8443 || port == 5443
}

func (p *GRPCPlugin) Priority() int    { return 500 } // pick any unused slot
func (p *GRPCTLSPlugin) Priority() int { return 501 }

/* ---------- runtime ---------- */

func (p *GRPCPlugin) Run(conn net.Conn, t time.Duration, tgt plugins.Target) (*plugins.Service, error) {
	return detectGRPC(conn, tgt, t, false)
}
func (p *GRPCTLSPlugin) Run(conn net.Conn, t time.Duration, tgt plugins.Target) (*plugins.Service, error) {
	return detectGRPC(conn, tgt, t, true)
}

/* ---------- detector ---------- */

// Minimum HTTP/2 client preface + empty SETTINGS frame.
var clientPreface = append(
	[]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
	// length(3) type(1) flags(1) reserved+streamid(4)
	[]byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}...,
)

func detectGRPC(conn net.Conn, tgt plugins.Target, timeout time.Duration, tls bool) (*plugins.Service, error) {
	// Send the preface; expect SETTINGS + maybe GOAWAY or HEADERS
	resp, err := utils.SendRecv(conn, clientPreface, timeout)
	if err != nil {
		return nil, err
	}
	if len(resp) == 0 {
		return nil, nil // no response, let next plugin try
	}

	// Very lightweight heuristics:
	prefaceAck := bytes.Contains(resp, []byte{0x00, 0x00, 0x00, 0x04}) // SETTINGS type=4
	// Optional extras – cheap checks that don’t require full protobuf parsing
	supportsReflection := bytes.Contains(resp, []byte("server reflection"))
	healthStatus := ""
	if bytes.Contains(resp, []byte("grpc-status")) {
		healthStatus = "responded"
	}

	meta := GRPCMetadata{
		PrefaceAck:         prefaceAck,
		SupportsReflection: supportsReflection,
		HealthStatus:       healthStatus,
	}

	transport := plugins.TCP
	if tls {
		transport = plugins.TCPTLS
	}

	return plugins.CreateServiceFrom(tgt, meta, tls, "", transport), nil
}
