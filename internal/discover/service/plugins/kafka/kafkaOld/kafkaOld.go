// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package kafkaold

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math"
	"math/big"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

type Plugin struct{}
type TLSPlugin struct{}

const KAFKA = "kafkaOld"
const KAFKATLS = "KafkaOldTLS"

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	result, err := Run(conn, false, timeout, target)
	return result, err
}
func (p *Plugin) PortPriority(i uint16) bool {
	return i == 9092
}
func (p *Plugin) Priority() int {
	return 201
}
func (p *TLSPlugin) Priority() int {
	return 201
}
func (p *Plugin) Name() string {
	return KAFKA
}
func (p *Plugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	result, err := Run(conn, true, timeout, target)
	return result, err
}
func (p *TLSPlugin) PortPriority(i uint16) bool {
	return i == 9093
}
func (p *TLSPlugin) Name() string {
	return KAFKATLS
}
func (p *TLSPlugin) Type() common.TransportType {
	return common.TransportTypeTcptls
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
func Run(conn net.Conn, tls bool, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {

	notReportError, err := checkMetadataQuery(conn, timeout)
	if err != nil {
		if !notReportError {
			return nil, err
		}
		return nil, nil
	}
	if !notReportError {
		return nil, nil
	}
	return helpers.MetadataResult(target, ServiceKafka{}, tls, "<=0.9.0.X", common.TransportTypeTcp), nil
}

/* Helper function to generate a correlation_id */
/* Might update to be random later */
func genCorrelationID() []byte {
	cid := []byte{0x1e, 0x33, 0xf4, 0x81}
	return cid
}

/* Helper function for generating a random alphanumeric string */
func genRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	str := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", &utils.RandomizeError{Message: "KafkaRandomString"}
		}
		str[i] = charset[num.Int64()]
	}

	return string(str), nil
}
func checkMetadataQuery(conn net.Conn, timeout time.Duration) (bool, error) {
	cid := genCorrelationID()
	topicName, err := genRandomString(6)
	if err != nil {
		return false, err
	}
	metadataRequest := []byte{

		0x00, 0x00, 0x00, 0x00,

		0x00, 0x03,

		0x00, 0x00,

		cid[0], cid[1], cid[2], cid[3],

		0x00, 0x0d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x63,
		0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2d, 0x35,

		0x00, 0x00, 0x00, 0x01,

		0x00, 0x06, topicName[0], topicName[1], topicName[2], topicName[3],
		topicName[4], topicName[5],
	}

	packetLength := make([]byte, 4)
	binary.BigEndian.PutUint32(packetLength, uint32(len(metadataRequest)-4))
	for i := 0; i < 4; i++ {
		metadataRequest[i] = packetLength[i]
	}

	response, err := utils.SendRecv(conn, metadataRequest, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, &utils.ServerNotEnable{}
	}

	responseLength := binary.BigEndian.Uint32(response[0:4])
	expectedLength := uint32(math.Max(float64(len(response)-4), 0))
	if responseLength != expectedLength {
		return false, nil
	}

	correlationID := response[4:8]
	for i := 0; i < 4; i++ {
		if cid[i] != correlationID[i] {
			return false, nil
		}
	}

	brokerIndex := uint16(8)
	brokerCount := binary.BigEndian.Uint32(response[brokerIndex : brokerIndex+4])

	index := brokerIndex + 4
	for i := uint32(0); i < brokerCount; i++ {

		hostLength := binary.BigEndian.Uint16(response[index+4 : index+6])
		index += 4 + 2 + hostLength + 4
	}

	topicsIndex := index

	topicsIndex += 4
	topicsIndex += 2
	topicNameLength := binary.BigEndian.Uint16(response[topicsIndex : topicsIndex+2])
	topicsIndex += 2
	tName := string(response[topicsIndex : topicsIndex+topicNameLength])

	if tName != topicName {
		return false, nil
	}

	return true, nil
}

var defaultPluginPorts = helpers.Ports((&Plugin{}).PortPriority)

func (p *Plugin) DefaultPorts() []int { return defaultPluginPorts }
func (p *Plugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}

var defaultTLSPluginPorts = helpers.Ports((&TLSPlugin{}).PortPriority)

func (p *TLSPlugin) DefaultPorts() []int { return defaultTLSPluginPorts }
func (p *TLSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
