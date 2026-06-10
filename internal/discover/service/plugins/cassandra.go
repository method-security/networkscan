package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

const (
	cassandraOpcodeOptions   byte = 0x05
	cassandraOpcodeSupported byte = 0x06
	cassandraMaxBodyLength        = 64 * 1024
)

type CassandraFingerprinter struct{}

func (CassandraFingerprinter) Name() string { return "cassandra" }

func (CassandraFingerprinter) DefaultPorts() []int { return []int{9042} }

func (CassandraFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	for _, version := range []byte{0x05, 0x04, 0x03} {
		response, err := queryCassandraSupported(ctx, ip, port, timeout, version)
		if err != nil {
			continue
		}
		return buildCassandraResult(host, ip, port, response), nil
	}
	return nil, fmt.Errorf("not Cassandra")
}

type cassandraSupportedResponse struct {
	nativeProtocolVersion byte
	supported             map[string][]string
}

func queryCassandraSupported(ctx context.Context, ip net.IP, port int, timeout int, version byte) (*cassandraSupportedResponse, error) {
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write(cassandraOptionsFrame(version)); err != nil {
		return nil, err
	}

	header := make([]byte, 9)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	if header[0]&0x80 == 0 {
		return nil, fmt.Errorf("cassandra response bit not set")
	}
	if header[4] != cassandraOpcodeSupported {
		return nil, fmt.Errorf("unexpected cassandra opcode 0x%02x", header[4])
	}

	bodyLength := binary.BigEndian.Uint32(header[5:9])
	if bodyLength > cassandraMaxBodyLength {
		return nil, fmt.Errorf("cassandra response too large: %d", bodyLength)
	}

	body := make([]byte, int(bodyLength))
	if bodyLength > 0 {
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, err
		}
	}

	supported, err := parseCassandraStringMultimap(body)
	if err != nil {
		return nil, err
	}

	return &cassandraSupportedResponse{
		nativeProtocolVersion: header[0] & 0x7f,
		supported:             supported,
	}, nil
}

func cassandraOptionsFrame(version byte) []byte {
	return []byte{
		version,    // request protocol version
		0x00,       // flags
		0x00, 0x01, // stream id
		cassandraOpcodeOptions, // OPTIONS
		0x00, 0x00, 0x00, 0x00, // body length
	}
}

func parseCassandraStringMultimap(body []byte) (map[string][]string, error) {
	reader := cassandraBodyReader{body: body}
	count, err := reader.readShort()
	if err != nil {
		return nil, err
	}

	result := make(map[string][]string, int(count))
	for i := 0; i < int(count); i++ {
		key, err := reader.readString()
		if err != nil {
			return nil, err
		}
		valueCount, err := reader.readShort()
		if err != nil {
			return nil, err
		}
		values := make([]string, 0, int(valueCount))
		for j := 0; j < int(valueCount); j++ {
			value, err := reader.readString()
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		result[key] = values
	}

	return result, nil
}

type cassandraBodyReader struct {
	body []byte
	pos  int
}

func (r *cassandraBodyReader) readShort() (uint16, error) {
	if len(r.body)-r.pos < 2 {
		return 0, fmt.Errorf("truncated cassandra response")
	}
	value := binary.BigEndian.Uint16(r.body[r.pos : r.pos+2])
	r.pos += 2
	return value, nil
}

func (r *cassandraBodyReader) readString() (string, error) {
	length, err := r.readShort()
	if err != nil {
		return "", err
	}
	if len(r.body)-r.pos < int(length) {
		return "", fmt.Errorf("truncated cassandra string")
	}
	value := string(r.body[r.pos : r.pos+int(length)])
	r.pos += int(length)
	return value, nil
}

func buildCassandraResult(host string, ip net.IP, port int, response *cassandraSupportedResponse) *discoverfern.ServiceDetails {
	version := "Cassandra"
	if cqlVersions := response.supported["CQL_VERSION"]; len(cqlVersions) > 0 {
		version = "CQL " + strings.Join(cqlVersions, ",")
	}

	metadata := map[string]string{
		"application_protocol":      "CASSANDRA",
		"native_protocol_version":   fmt.Sprintf("%d", response.nativeProtocolVersion),
		"native_protocol_operation": "OPTIONS",
		"native_protocol_response":  "SUPPORTED",
	}
	if cqlVersions := response.supported["CQL_VERSION"]; len(cqlVersions) > 0 {
		metadata["cql_versions"] = strings.Join(cqlVersions, ",")
	}
	if compression := response.supported["COMPRESSION"]; len(compression) > 0 {
		metadata["compression"] = strings.Join(compression, ",")
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Version:   &version,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeCassandra,
		Metadata:  &discoverfern.ServiceMetadata{Generic: &discoverfern.GenericServiceMetadata{Metadata: metadata}},
	}
}
