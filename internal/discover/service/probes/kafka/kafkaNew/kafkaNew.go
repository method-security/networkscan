// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package kafkanew

import (
	"context"
	"encoding/binary"
	"math"
	"net"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

type Plugin struct{}
type TLSPlugin struct{}

const KAFKA = "kafkaNew"
const KAFKATLS = "KafkaNewTLS"

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	result, err := Run(conn, false, timeout, target)
	return result, err
}
func (p *Plugin) PortPriority(i uint16) bool {
	return i == 9092
}
func (p *Plugin) Name() string {
	return KAFKA
}
func (p *Plugin) Priority() int {
	return 200
}
func (p *TLSPlugin) Priority() int {
	return 200
}
func (p *Plugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	result, err := Run(conn, true, timeout, target)
	return result, err
}
func (p *TLSPlugin) PortPriority(i uint16) bool {
	return i == 9093
}
func (p *TLSPlugin) Name() string {
	return KAFKATLS
}
func (p *TLSPlugin) Type() probe.Protocol {
	return probe.TCPTLS
}

/*
Run Kafka scanner probe.

Primary Sources:
  - https://kafka.apache.org/protocol.html (Gold mine)
  - https://kafka.apache.org/documentation.html
  - https://kafka.apache.org/downloads

Methodology:
Scanning for Kafka is a bit tricky, so I've outlined my methodology here. Kafka
is harder to detect reliably for a few reasons:
  - Kafka brokers may optionally require authentication via SASL before most
    commands can be issued.
  - There are many different versions of Kafka, and most API calls work slightly
    different on each versions (especially for pre-0.9.0.X releases)

Fortunately, Kafka versions 0.10.0.0 and later support the ApiVersions request,
which can be sent by an unauthenticated user to check which API requests are
supported by the broker. Also versions prior to 0.9.0.0 do not offer any form of
authentication. And, all versions of Kafka are compatible with any older client.
This means that:
 1. If Kafka version 0.10.0.0 or higher is running, we can confirm with the
    ApiVersions request regardless of if authentication is required This
    includes any version of Kafka released since May, 2016.
 2. If Kafka version 0.8.0.X or earlier is running, we can confirm with a simple
    data query using API version 0.
 3. If Kafka version 0.9.0.X is running and does not require authentication, we
    can also confirm with a simple v0 data query.

I'm not sure if Kafka brokers running version 0.9.0.X that do require
authentication will be detected by any of the above methods. It's possible that
strategy 3 will still work in this situation, but I was not able to confirm due
to the difficulty of setting up a testing environment for an older version.
*/
func Run(conn net.Conn, tls bool, timeout time.Duration, target probe.Target) (*probe.Service, error) {

	notReportError, err := checkAPIVersions(conn, timeout)
	if err != nil {
		if !notReportError {
			return nil, err
		}
		return nil, nil
	}
	if !notReportError {
		return nil, nil
	}

	return probe.Result(target, probe.ServiceKafka{}, tls, ">=0.10.0.0", probe.TCP), nil
}

/* Helper function to generate a correlation_id */
/* Might update to be random later */
func genCorrelationID() []byte {
	cid := []byte{0x1e, 0x33, 0xf4, 0x81}
	return cid
}

/*
	checkApiVersions - sends an ApiVersions request and validates the output.

/*
/* Note that if the broker does not support ApiVersions, it might terminate the
/* TCP connection (source: https://kafka.apache.org/protocol.html#api_versions).
/*
/* The function sends an ApiVersions request because this is widely supported,
/* and does not require authentication. All Kafka responses start with the
/* packet length followed by the "correlation ID", which is a value specified by
/* the client and included in their request. So we check to make sure the first
/* four bytes (length) are equivalent to the size of the response data and the
/* next four bytes (correlation ID) match the ID included in the request.
/* Further reading: https://kafka.apache.org/protocol.html#protocol_messages
*/
func checkAPIVersions(conn net.Conn, timeout time.Duration) (bool, error) {
	cid := genCorrelationID()
	apiVersionsRequest := []byte{

		0x00, 0x00, 0x00, 0x43,

		0x00, 0x12,

		0x00, 0x00,

		cid[0], cid[1], cid[2], cid[3],

		0x00, 0x1f, 0x63, 0x6f, 0x6e, 0x73, 0x75, 0x6d,
		0x65, 0x72, 0x2d, 0x4f, 0x66, 0x66, 0x73, 0x65,
		0x74, 0x20, 0x45, 0x78, 0x70, 0x6c, 0x6f, 0x72,
		0x65, 0x72, 0x20, 0x32, 0x2e, 0x32, 0x2d, 0x31,
		0x38,

		0x00,

		0x12, 0x61, 0x70, 0x61, 0x63, 0x68, 0x65, 0x2d,
		0x6b, 0x61, 0x66, 0x6b, 0x61, 0x2d, 0x6a, 0x61,
		0x76, 0x61,

		0x06, 0x32, 0x2e, 0x34, 0x2e, 0x30,

		0x00,
	}

	response, err := utils.SendRecv(conn, apiVersionsRequest, timeout)
	if err != nil {
		return false, err
	}
	if len(response) < 8 {
		return true, &utils.ServerNotEnable{}
	}

	responseLength := binary.BigEndian.Uint32(response[0:4])
	expectedLength := uint32(math.Max(float64(len(response)-4), 0))
	correlationID := response[4:8]

	if responseLength != expectedLength {
		return false, nil
	}

	for i := 0; i < len(cid); i++ {
		if cid[i] != correlationID[i] {
			return false, nil
		}
	}

	return true, nil
}

var defaultPluginPorts = probe.Ports((&Plugin{}).PortPriority)

func (p *Plugin) DefaultPorts() []int { return defaultPluginPorts }
func (p *Plugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}

var defaultTLSPluginPorts = probe.Ports((&TLSPlugin{}).PortPriority)

func (p *TLSPlugin) DefaultPorts() []int { return defaultTLSPluginPorts }
func (p *TLSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
