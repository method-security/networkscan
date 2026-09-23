package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"unicode/utf8"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type KafkaNewFingerprinter struct{}
type KafkaNewTLSFingerprinter struct{}
type KafkaOldFingerprinter struct{}
type KafkaOldTLSFingerprinter struct{}

func (KafkaNewFingerprinter) Name() string           { return "kafkaNew" }
func (KafkaNewTLSFingerprinter) Name() string        { return "KafkaNewTLS" }
func (KafkaOldFingerprinter) Name() string           { return "kafkaOld" }
func (KafkaOldTLSFingerprinter) Name() string        { return "KafkaOldTLS" }
func (KafkaNewFingerprinter) DefaultPorts() []int    { return []int{9092} }
func (KafkaNewTLSFingerprinter) DefaultPorts() []int { return []int{9093} }
func (KafkaOldFingerprinter) DefaultPorts() []int    { return []int{9092} }
func (KafkaOldTLSFingerprinter) DefaultPorts() []int { return []int{9093} }
func (KafkaNewFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeKafka(ctx, ip, port, host, timeout, false, false)
}
func (KafkaNewTLSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeKafka(ctx, ip, port, host, timeout, true, false)
}
func (KafkaOldFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeKafka(ctx, ip, port, host, timeout, false, true)
}
func (KafkaOldTLSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeKafka(ctx, ip, port, host, timeout, true, true)
}

func detectNativeKafka(ctx context.Context, ip net.IP, port int, host string, timeout int, secure, legacy bool) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	keys := []uint16{18, 3}
	if legacy {
		keys = []uint16{3}
	}
	var lastErr error
	for _, key := range keys {
		metadata, err := nativeKafkaExchange(ctx, ip, port, host, timeout, secure, key)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		result := helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeKafka, "kafka", "", metadata)
		result.Tls = &secure
		return result, nil
	}
	return nil, lastErr
}

// Kafka's ApiVersions v0 works before SASL authentication. Metadata v0 is
// retained for brokers predating ApiVersions; neither request supplies credentials.
func nativeKafkaExchange(ctx context.Context, ip net.IP, port int, host string, timeout int, secure bool, key uint16) (map[string]string, error) {
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if secure {
		upgraded, e := helpers.UpgradeTLS(ctx, conn, host)
		if e != nil {
			return nil, e
		}
		conn = upgraded
	}
	const correlation uint32 = 0x4e534341
	request := make([]byte, 14)
	binary.BigEndian.PutUint16(request[4:6], key)
	binary.BigEndian.PutUint32(request[8:12], correlation)
	// Empty client ID; Metadata's empty topics array requests existing topics only.
	if key == 3 {
		request = append(request, 0, 0, 0, 0)
	}
	binary.BigEndian.PutUint32(request[:4], uint32(len(request)-4))
	if _, err = conn.Write(request); err != nil {
		return nil, err
	}
	var header [4]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n < 8 || n > 1<<20 {
		return nil, fmt.Errorf("invalid Kafka response size")
	}
	data := make([]byte, int(n))
	if _, err = io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint32(data[:4]) != correlation {
		return nil, fmt.Errorf("Kafka correlation mismatch")
	}
	if key == 18 {
		return nativeKafkaAPIs(data[4:])
	}
	return nativeKafkaMetadata(data[4:])
}

func nativeKafkaAPIs(data []byte) (map[string]string, error) {
	if len(data) < 6 {
		return nil, io.ErrUnexpectedEOF
	}
	code := binary.BigEndian.Uint16(data[:2])
	count := binary.BigEndian.Uint32(data[2:6])
	if (code != 0 && code != 35) || count == 0 || count > 4096 || len(data)-6 != int(count)*6 {
		return nil, fmt.Errorf("invalid Kafka API list")
	}
	versions := map[string]string{}
	for offset := 6; offset < len(data); offset += 6 {
		key := int16(binary.BigEndian.Uint16(data[offset:]))
		min := int16(binary.BigEndian.Uint16(data[offset+2:]))
		max := int16(binary.BigEndian.Uint16(data[offset+4:]))
		id := strconv.Itoa(int(key))
		if key < 0 || min < 0 || max < min || versions[id] != "" {
			return nil, fmt.Errorf("invalid Kafka API range")
		}
		versions[id] = fmt.Sprintf("%d-%d", min, max)
	}
	encoded, _ := json.Marshal(versions)
	return map[string]string{"api_versions": string(encoded), "error_code": strconv.Itoa(int(code)), "discovery_api": "ApiVersions"}, nil
}

// All counts are checked against the remaining bounded frame before iteration.
func nativeKafkaMetadata(data []byte) (map[string]string, error) {
	r := bytes.NewReader(data)
	read32 := func() (int32, error) { var n int32; err := binary.Read(r, binary.BigEndian, &n); return n, err }
	count := func(min int) (int, error) {
		n, err := read32()
		if err != nil || n < 0 || int64(n)*int64(min) > int64(r.Len()) {
			return 0, fmt.Errorf("invalid Kafka array")
		}
		return int(n), nil
	}
	readString := func() (string, error) {
		var n int16
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return "", err
		}
		if n < 0 || int(n) > r.Len() {
			return "", fmt.Errorf("invalid Kafka string length")
		}
		b := make([]byte, n)
		_, _ = io.ReadFull(r, b)
		if !utf8.Valid(b) {
			return "", fmt.Errorf("invalid Kafka string")
		}
		return string(b), nil
	}
	n, err := count(10)
	if err != nil {
		return nil, err
	}
	brokers := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id, e := read32()
		if e != nil || id < 0 {
			return nil, fmt.Errorf("invalid Kafka broker ID")
		}
		host, e := readString()
		if e != nil || host == "" {
			return nil, fmt.Errorf("invalid Kafka broker host")
		}
		port, e := read32()
		if e != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid Kafka broker port")
		}
		brokers = append(brokers, net.JoinHostPort(host, strconv.Itoa(int(port))))
	}
	topics, err := count(8)
	if err != nil {
		return nil, err
	}
	for i := 0; i < topics; i++ {
		var code int16
		if err = binary.Read(r, binary.BigEndian, &code); err != nil || code < -1 {
			return nil, fmt.Errorf("invalid Kafka topic error")
		}
		if _, err = readString(); err != nil {
			return nil, err
		}
		partitions, e := count(18)
		if e != nil {
			return nil, e
		}
		for j := 0; j < partitions; j++ {
			var partition struct {
				Error  int16
				Index  int32
				Leader int32
			}
			if err = binary.Read(r, binary.BigEndian, &partition); err != nil || partition.Error < -1 || partition.Index < 0 || partition.Leader < -1 {
				return nil, fmt.Errorf("invalid Kafka partition")
			}
			for k := 0; k < 2; k++ {
				nodes, e := count(4)
				if e != nil {
					return nil, e
				}
				for l := 0; l < nodes; l++ {
					id, e := read32()
					if e != nil || id < 0 {
						return nil, fmt.Errorf("invalid Kafka replica")
					}
				}
			}
		}
	}
	if r.Len() != 0 || (n == 0 && topics == 0) {
		return nil, fmt.Errorf("empty or trailing Kafka metadata")
	}
	encoded, _ := json.Marshal(brokers)
	return map[string]string{"brokers": string(encoded), "topic_count": strconv.Itoa(topics), "discovery_api": "Metadata"}, nil
}
