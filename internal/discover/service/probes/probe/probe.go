// Package probe contains connection lifecycle and result helpers for wire-level service probes.
package probe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/common/ntlm"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	rdpwire "github.com/Method-Security/networkscan/internal/protocol/rdp"
)

type Service = discover.ServiceDetails
type Protocol uint8

const (
	TCP Protocol = iota
	TCPTLS
	UDP
)

type Target struct {
	Address netip.AddrPort
	Host    string
	Context context.Context
}

type Metadata interface{ Type() string }

// Ports evaluates a protocol's port predicate once, when its package is initialized.
func Ports(matches func(uint16) bool) []int {
	var ports []int
	for port := 1; port <= 65535; port++ {
		if matches(uint16(port)) {
			ports = append(ports, port)
		}
	}
	return ports
}

func Detect(ctx context.Context, ip net.IP, port int, host string, timeout int, name string, transport Protocol, run func(net.Conn, time.Duration, Target) (*Service, error)) (*Service, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid service endpoint")
	}
	target := Target{Address: netip.AddrPortFrom(addr.Unmap(), uint16(port)), Host: host, Context: ctx}
	network := "tcp"
	if transport == UDP {
		network = "udp"
	}
	conn, err := helpers.Dial(ctx, network, target.Address.String(), timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if transport == TCPTLS {
		if strings.EqualFold(name, "rdp") {
			if err := rdpwire.WriteX224ConnectionRequest(conn, "", rdpwire.RequestAllProtocols); err != nil {
				return nil, err
			}
			confirm, err := rdpwire.ReadX224ConnectionConfirm(conn)
			if err != nil {
				return nil, err
			}
			if !confirm.NegResponseReceived || confirm.SelectedProtocol == 0 {
				return nil, nil
			}
		}
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = tlsConn
	}
	result, err := run(conn, helpers.Timeout(timeout), target)
	if result != nil {
		// MQTT version is a plugin property; the shared packet metadata does not distinguish it.
		if strings.HasPrefix(strings.ToLower(name), "mqtt3") {
			result.Protocol = common.ProtocolTypeMqtt3
		}
		if strings.HasPrefix(strings.ToLower(name), "mqtt5") {
			result.Protocol = common.ProtocolTypeMqtt5
		}
	}
	return result, err
}

// Result emits the same Fern report shape as the existing service plugins.
func Result(target Target, payload Metadata, tlsEnabled bool, version string, transport Protocol) *Service {
	if payload == nil {
		return nil
	}
	name := strings.ToUpper(payload.Type())
	switch name {
	case "MILVUS-METRICS":
		name = "MILVUS"
	case "JAVA-RMI":
		name = "JAVARMI"
	case "ORACLE":
		name = "ORACLEDB"
	}
	protocol, err := common.NewProtocolTypeFromString(name)
	if err != nil {
		return nil
	}
	metadata := map[string]string{}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil
	}
	for k, v := range fields {
		metadata[k] = fmt.Sprintf("%v", v)
	}
	if osVersion := metadata["osVersion"]; osVersion != "" {
		parts := strings.Split(osVersion, ".")
		if len(parts) >= 3 {
			metadata["mappedOsVersion"] = ntlm.ParseWindowsVersion("Build " + parts[2])
		}
	}
	wireTransport := common.TransportTypeTcp
	if transport == UDP {
		wireTransport = common.TransportTypeUdp
	}
	return &Service{Host: target.Host, Ip: target.Address.Addr().String(), Port: int(target.Address.Port()), Tls: &tlsEnabled, Version: &version, Transport: wireTransport, Protocol: protocol, Metadata: &discover.ServiceMetadata{Generic: &discover.GenericServiceMetadata{Metadata: metadata}}}
}
