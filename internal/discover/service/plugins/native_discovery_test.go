package plugins

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
)

type nativeDiscoveryProbe interface {
	Name() string
	DefaultPorts() []int
	Detect(context.Context, net.IP, int, string, int) (*discover.ServiceDetails, error)
}

type nativeDiscoveryCase struct {
	probe    nativeDiscoveryProbe
	name     string
	port     int
	protocol common.ProtocolType
	tls      bool
	kind     string
}

func nativeDiscoveryCases() []nativeDiscoveryCase {
	return []nativeDiscoveryCase{
		{Neo4jFingerprinter{}, "neo4j", 7687, common.ProtocolTypeNeo4J, false, "bolt"},
		{Neo4jTLSFingerprinter{}, "neo4j", 7687, common.ProtocolTypeNeo4J, true, "bolt"},
		{KafkaNewFingerprinter{}, "kafkaNew", 9092, common.ProtocolTypeKafka, false, "apis"},
		{KafkaNewTLSFingerprinter{}, "KafkaNewTLS", 9093, common.ProtocolTypeKafka, true, "apis"},
		{KafkaOldFingerprinter{}, "kafkaOld", 9092, common.ProtocolTypeKafka, false, "metadata"},
		{KafkaOldTLSFingerprinter{}, "KafkaOldTLS", 9093, common.ProtocolTypeKafka, true, "metadata"},
		{MQTT3Fingerprinter{}, "mqtt3", 1883, common.ProtocolTypeMqtt3, false, "mqtt3"},
		{MQTT3TLSFingerprinter{}, "mqtt3tls", 8883, common.ProtocolTypeMqtt3, true, "mqtt3"},
		{MQTT5Fingerprinter{}, "mqtt5", 1883, common.ProtocolTypeMqtt5, false, "mqtt5"},
		{MQTT5TLSFingerprinter{}, "mqtt5tls", 8883, common.ProtocolTypeMqtt5, true, "mqtt5"},
		{LDAPDiscoveryFingerprinter{}, "ldap", 389, common.ProtocolTypeLdap, false, "ldap"},
		{LDAPTLSFingerprinter{}, "ldaps", 636, common.ProtocolTypeLdaps, true, "ldap"},
	}
}

func nativeDiscoveryListener(t *testing.T, secure bool, scripts ...func(net.Conn) error) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if secure {
		certServer := httptest.NewTLSServer(nil)
		config := &tls.Config{Certificates: certServer.TLS.Certificates, MinVersion: tls.VersionTLS12}
		certServer.Close()
		listener = tls.NewListener(listener, config)
	}
	done := make(chan error, 1)
	go func() {
		for _, script := range scripts {
			conn, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			err = script(conn)
			_ = conn.Close()
			if err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(4 * time.Second):
			t.Error("loopback server did not finish")
		}
	})
	return port
}

func nativeDiscoveryReadRequest(conn net.Conn, kind string) error {
	var request []byte
	switch kind {
	case "bolt":
		request = make([]byte, 20)
		if _, err := io.ReadFull(conn, request); err != nil {
			return err
		}
		if !bytes.Equal(request[:4], []byte{0x60, 0x60, 0xb0, 0x17}) {
			return fmt.Errorf("missing Bolt magic")
		}
	case "apis", "metadata":
		var header [4]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(header[:])
		if n < 10 || n > 128 {
			return fmt.Errorf("bad Kafka request size")
		}
		request = make([]byte, n)
		if _, err := io.ReadFull(conn, request); err != nil {
			return err
		}
		key := uint16(18)
		if kind == "metadata" {
			key = 3
		}
		if binary.BigEndian.Uint16(request[:2]) != key || binary.BigEndian.Uint16(request[2:4]) != 0 {
			return fmt.Errorf("unexpected Kafka API")
		}
		if kind == "metadata" && !bytes.Equal(request[10:], []byte{0, 0, 0, 0}) {
			return fmt.Errorf("metadata must not name/create topics")
		}
	case "mqtt3", "mqtt5":
		var header [2]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return err
		}
		if header[0] != 0x10 || header[1] > 64 {
			return fmt.Errorf("bad MQTT CONNECT")
		}
		request = make([]byte, header[1])
		if _, err := io.ReadFull(conn, request); err != nil {
			return err
		}
		expected := []byte{0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 10, 0, 0}
		if kind == "mqtt5" {
			expected = []byte{0, 4, 'M', 'Q', 'T', 'T', 5, 2, 0, 10, 0, 0, 0}
		}
		if !bytes.Equal(request, expected) {
			return fmt.Errorf("unexpected MQTT CONNECT: %x", request)
		}
	case "ldap":
		request = make([]byte, 14)
		if _, err := io.ReadFull(conn, request); err != nil {
			return err
		}
		if !bytes.Equal(request, []byte{0x30, 12, 2, 1, 1, 0x60, 7, 2, 1, 3, 4, 0, 0x80, 0}) {
			return fmt.Errorf("not an anonymous LDAPv3 bind: %x", request)
		}
	}
	return nil
}

func nativeDiscoveryReply(kind string) []byte {
	switch kind {
	case "bolt":
		return []byte{0, 0, 4, 4}
	case "mqtt3":
		return []byte{0x20, 2, 0, 0}
	case "mqtt5":
		return []byte{0x20, 3, 0, 0, 0}
	case "ldap":
		return []byte{0x30, 12, 2, 1, 1, 0x61, 7, 10, 1, 0, 4, 0, 4, 0}
	case "apis":
		return nativeDiscoveryKafkaFrame([]byte{0, 0, 0, 0, 0, 1, 0, 18, 0, 0, 0, 4})
	case "metadata":
		return nativeDiscoveryKafkaFrame([]byte{0, 0, 0, 1, 0, 0, 0, 1, 0, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0, 0, 0x23, 0x84, 0, 0, 0, 0})
	}
	return nil
}

func nativeDiscoveryKafkaFrame(body []byte) []byte {
	frame := make([]byte, 8)
	binary.BigEndian.PutUint32(frame, uint32(4+len(body)))
	binary.BigEndian.PutUint32(frame[4:], 0x4e534341)
	return append(frame, body...)
}

func nativeDiscoveryRespond(kind string, response []byte) func(net.Conn) error {
	return func(conn net.Conn) error {
		if err := nativeDiscoveryReadRequest(conn, kind); err != nil {
			return err
		}
		// Fragment every response to exercise stream framing, not single-read luck.
		for _, b := range response {
			if _, err := conn.Write([]byte{b}); err != nil {
				return nil
			}
		}
		return nil
	}
}

func TestNativeDiscoveryVariants(t *testing.T) {
	for _, tc := range nativeDiscoveryCases() {
		t.Run(fmt.Sprintf("%T", tc.probe), func(t *testing.T) {
			if tc.probe.Name() != tc.name || !reflect.DeepEqual(tc.probe.DefaultPorts(), []int{tc.port}) {
				t.Fatal("inventory changed")
			}
			port := nativeDiscoveryListener(t, tc.tls, nativeDiscoveryRespond(tc.kind, nativeDiscoveryReply(tc.kind)))
			result, err := tc.probe.Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || result.Protocol != tc.protocol || result.Transport != common.TransportTypeTcp || result.Tls == nil || *result.Tls != tc.tls {
				t.Fatalf("wrong service: %#v", result)
			}
			if result.Metadata.Generic.Metadata["application_protocol"] == "" {
				t.Fatal("missing native metadata")
			}
			metadata := result.Metadata.Generic.Metadata
			want := map[string]map[string]string{
				"bolt":     {"bolt_version": "4.4"},
				"apis":     {"api_versions": `{"18":"0-4"}`, "discovery_api": "ApiVersions"},
				"metadata": {"brokers": `["localhost:9092"]`, "topic_count": "0"},
				"mqtt3":    {"return_code": "0"},
				"mqtt5":    {"return_code": "0"},
				"ldap":     {"result_code": "0", "anonymous_bind_allowed": "true"},
			}
			for key, value := range want[tc.kind] {
				if metadata[key] != value {
					t.Errorf("metadata %s = %q, want %q", key, metadata[key], value)
				}
			}
		})
	}
}

func TestNativeDiscoveryAuthRejections(t *testing.T) {
	for _, tc := range nativeDiscoveryCases() {
		if tc.kind != "mqtt3" && tc.kind != "mqtt5" && tc.kind != "ldap" {
			continue
		}
		t.Run(fmt.Sprintf("%T", tc.probe), func(t *testing.T) {
			response := nativeDiscoveryReply(tc.kind)
			switch tc.kind {
			case "mqtt3":
				response[3] = 5
			case "mqtt5":
				response[3] = 0x87
			case "ldap":
				response[9] = 49
			}
			port := nativeDiscoveryListener(t, tc.tls, nativeDiscoveryRespond(tc.kind, response))
			result, err := tc.probe.Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
			if err != nil || result == nil {
				t.Fatalf("auth refusal lost service: %v", err)
			}
		})
	}
}

func TestNativeDiscoveryCancellation(t *testing.T) {
	for _, tc := range nativeDiscoveryCases() {
		t.Run(fmt.Sprintf("%T", tc.probe), func(t *testing.T) {
			port := nativeDiscoveryListener(t, tc.tls, func(conn net.Conn) error { _, _ = io.Copy(io.Discard, conn); return nil })
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			result, err := tc.probe.Detect(ctx, net.ParseIP("127.0.0.1"), port, "localhost", -1)
			if err == nil || result != nil || time.Since(start) > time.Second {
				t.Fatalf("cancellation failed: %v %v", result, err)
			}
		})
	}
}

func TestNativeDiscoveryTLSHandshakeCancellation(t *testing.T) {
	for _, tc := range nativeDiscoveryCases() {
		if !tc.tls {
			continue
		}
		t.Run(fmt.Sprintf("%T", tc.probe), func(t *testing.T) {
			port := nativeDiscoveryListener(t, false, func(conn net.Conn) error { _, _ = io.Copy(io.Discard, conn); return nil })
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			result, err := tc.probe.Detect(ctx, net.ParseIP("127.0.0.1"), port, "localhost", -1)
			if err == nil || result != nil {
				t.Fatal("stalled TLS handshake accepted")
			}
		})
	}
}

func TestNativeDiscoveryMalformed(t *testing.T) {
	cases := []struct {
		name, kind string
		probe      nativeDiscoveryProbe
		response   []byte
	}{
		{"bolt-unoffered", "bolt", Neo4jFingerprinter{}, []byte{0, 0, 9, 5}},
		{"bolt-range-response", "bolt", Neo4jFingerprinter{}, []byte{0, 1, 4, 4}},
		{"bolt-truncated", "bolt", Neo4jFingerprinter{}, []byte{0, 0, 4}},
		{"mqtt3-bad-code", "mqtt3", MQTT3Fingerprinter{}, []byte{0x20, 2, 0, 6}},
		{"mqtt3-flags", "mqtt3", MQTT3Fingerprinter{}, []byte{0x21, 2, 0, 0}},
		{"mqtt3-session", "mqtt3", MQTT3Fingerprinter{}, []byte{0x20, 2, 1, 0}},
		{"mqtt5-bad-code", "mqtt5", MQTT5Fingerprinter{}, []byte{0x20, 3, 0, 1, 0}},
		{"mqtt5-length", "mqtt5", MQTT5Fingerprinter{}, []byte{0x20, 0xff, 0xff, 0xff, 0xff, 0}},
		{"mqtt5-huge", "mqtt5", MQTT5Fingerprinter{}, []byte{0x20, 0x80, 0x80, 0x04}},
		{"mqtt5-property-truncated", "mqtt5", MQTT5Fingerprinter{}, []byte{0x20, 4, 0, 0, 1, 0x1f}},
		{"mqtt5-property-unknown", "mqtt5", MQTT5Fingerprinter{}, []byte{0x20, 4, 0, 0, 1, 0x7f}},
		{"ldap-message-id", "ldap", LDAPDiscoveryFingerprinter{}, []byte{0x30, 12, 2, 1, 2, 0x61, 7, 10, 1, 0, 4, 0, 4, 0}},
		{"ldap-wrong-operation", "ldap", LDAPDiscoveryFingerprinter{}, []byte{0x30, 12, 2, 1, 1, 0x65, 7, 10, 1, 0, 4, 0, 4, 0}},
		{"ldap-indefinite", "ldap", LDAPDiscoveryFingerprinter{}, []byte{0x30, 0x80, 0, 0}},
		{"ldap-huge", "ldap", LDAPDiscoveryFingerprinter{}, []byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}},
		{"ldap-malformed-control", "ldap", LDAPDiscoveryFingerprinter{}, []byte{0x30, 15, 2, 1, 1, 0x61, 7, 10, 1, 0, 4, 0, 4, 0, 0xa0, 1, 0}},
		{"kafka-huge", "metadata", KafkaOldFingerprinter{}, []byte{0x7f, 0xff, 0xff, 0xff}},
		{"kafka-empty", "metadata", KafkaOldFingerprinter{}, nativeDiscoveryKafkaFrame(make([]byte, 8))},
		{"kafka-truncated", "metadata", KafkaOldFingerprinter{}, nativeDiscoveryKafkaFrame([]byte{0, 0, 0, 1})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port := nativeDiscoveryListener(t, false, nativeDiscoveryRespond(tc.kind, tc.response))
			result, err := tc.probe.Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 1)
			if err == nil || result != nil {
				t.Fatalf("malformed reply accepted: %#v", result)
			}
		})
	}
}

func TestNativeDiscoveryKafkaFallback(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprint(secure), func(t *testing.T) {
			port := nativeDiscoveryListener(t, secure, func(conn net.Conn) error { return nativeDiscoveryReadRequest(conn, "apis") }, nativeDiscoveryRespond("metadata", nativeDiscoveryReply("metadata")))
			var probe nativeDiscoveryProbe = KafkaNewFingerprinter{}
			if secure {
				probe = KafkaNewTLSFingerprinter{}
			}
			result, err := probe.Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
			if err != nil || result == nil {
				t.Fatalf("legacy fallback failed: %v", err)
			}
			if result.Metadata.Generic.Metadata["discovery_api"] != "Metadata" {
				t.Fatal("not legacy metadata")
			}
		})
	}
}

func TestNativeDiscoveryBoltLegacy(t *testing.T) {
	port := nativeDiscoveryListener(t, false, nativeDiscoveryRespond("bolt", []byte{0, 0, 0, 0}), nativeDiscoveryRespond("bolt", []byte{0, 0, 0, 1}))
	result, err := (Neo4jFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
	if err != nil || result == nil || result.Metadata.Generic.Metadata["bolt_version"] != "1.0" {
		t.Fatalf("Bolt 1 fallback failed: %v", err)
	}
}

func TestNativeDiscoveryParserControls(t *testing.T) {
	for _, data := range [][]byte{
		{0, 0, 0, 0, 0, 1, 0, 18, 0, 4, 0, 0},    // reversed API range
		{0, 0, 0xff, 0xff, 0xff, 0xff},           // negative array
		{0, 0, 0, 0, 0, 0},                       // empty API list
		{0, 0, 0, 0, 0, 1, 0, 18, 0, 0, 0, 4, 0}, // trailing byte
	} {
		if _, err := nativeKafkaAPIs(data); err == nil {
			t.Fatalf("accepted API list: %x", data)
		}
	}
	for _, data := range [][]byte{
		{4, 0x25, 1, 0x25, 1}, // duplicate retain available
		{2, 0x24, 2},          // invalid maximum QoS
		{3, 0x21, 0, 0},       // invalid receive maximum
		{3, 0x16, 0, 0},       // auth data without method
		{4, 0x1f, 0, 1, 0xff}, // invalid UTF-8
	} {
		if err := nativeMQTTProperties(data, map[string]string{}); err == nil {
			t.Fatalf("accepted properties: %x", data)
		}
	}
	metadata := map[string]string{}
	if err := nativeMQTTProperties([]byte{5, 0x1f, 0, 2, 'o', 'k'}, metadata); err != nil || metadata["reason_string"] != "ok" {
		t.Fatalf("valid properties: %v", err)
	}
	if err := nativeLDAPBERBounds([]byte{0x30, 4, 4, 0x84, 0xff, 0xff}, 0); err == nil {
		t.Fatal("nested BER length accepted")
	}
}

func TestNativeDiscoveryKafkaCorrelation(t *testing.T) {
	badAPI := nativeDiscoveryReply("apis")
	badAPI[7] ^= 1
	badMetadata := nativeDiscoveryReply("metadata")
	badMetadata[7] ^= 1
	port := nativeDiscoveryListener(t, false, nativeDiscoveryRespond("apis", badAPI), nativeDiscoveryRespond("metadata", badMetadata))
	result, err := (KafkaNewFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
	if err == nil || result != nil {
		t.Fatal("uncorrelated Kafka replies accepted")
	}
}

func TestNativeDiscoveryKafkaTopicMetadata(t *testing.T) {
	data := nativeDiscoveryReply("metadata")[8:]
	data = append([]byte(nil), data[:len(data)-4]...)
	// One existing topic with one partition, one replica and one in-sync replica.
	data = append(data, 0, 0, 0, 1, 0, 0, 0, 1, 'x', 0, 0, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1)
	metadata, err := nativeKafkaMetadata(data)
	if err != nil || metadata["topic_count"] != "1" {
		t.Fatalf("topic metadata failed: %v", err)
	}
	for i := 0; i < len(data); i++ {
		if _, err := nativeKafkaMetadata(data[:i]); err == nil {
			t.Fatalf("accepted truncation at %d", i)
		}
	}
}

func TestNativeDiscoveryLDAPControls(t *testing.T) {
	// BindResponse followed by a control with OID 1.2.3, criticality and value.
	response := nativeDiscoveryReply("ldap")
	response[1] += 18
	response = append(response, 0xa0, 16, 0x30, 14, 4, 5, '1', '.', '2', '.', '3', 1, 1, 0xff, 4, 2, 'o', 'k')
	port := nativeDiscoveryListener(t, false, nativeDiscoveryRespond("ldap", response))
	result, err := (LDAPDiscoveryFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
	if err != nil || result == nil {
		t.Fatalf("valid LDAP control rejected: %v", err)
	}
}

func TestNativeDiscoveryScannerTimeout(t *testing.T) {
	port := nativeDiscoveryListener(t, false, func(conn net.Conn) error { _, _ = io.Copy(io.Discard, conn); return nil })
	start := time.Now()
	result, err := (MQTT5Fingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 1)
	if err == nil || result != nil || time.Since(start) > 2*time.Second {
		t.Fatalf("scanner timeout failed: %v", err)
	}
}

func TestNativeDiscoveryBoltServerMetadata(t *testing.T) {
	for _, version := range [][2]byte{{1, 0}, {2, 0}, {3, 0}, {4, 4}, {5, 0}, {5, 1}, {5, 3}, {5, 8}} {
		for _, secure := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d.%d/tls=%v", version[0], version[1], secure), func(t *testing.T) {
				script := func(conn net.Conn) error {
					if err := nativeDiscoveryReadRequest(conn, "bolt"); err != nil {
						return err
					}
					if _, err := conn.Write([]byte{0, 0, version[1], version[0]}); err != nil {
						return err
					}
					request, err := nativeDiscoveryReadBoltChunk(conn)
					if err != nil {
						return err
					}
					if len(request) < 3 || request[1] != 1 || !bytes.Contains(request, []byte("networkscan/1")) {
						return fmt.Errorf("invalid HELLO/INIT")
					}
					if bytes.Contains(request, []byte("credentials")) || bytes.Contains(request, []byte("principal")) {
						return fmt.Errorf("credentials sent")
					}
					if version[0] <= 2 {
						if request[0] != 0xb2 {
							return fmt.Errorf("expected INIT")
						}
					} else if request[0] != 0xb1 {
						return fmt.Errorf("expected HELLO")
					}
					wantScheme := version[0] < 5 || version[1] == 0
					if bytes.Contains(request, []byte("scheme")) != wantScheme {
						return fmt.Errorf("wrong auth token presence")
					}
					wantAgent := version[0] == 5 && version[1] >= 3
					if bytes.Contains(request, []byte("bolt_agent")) != wantAgent {
						return fmt.Errorf("wrong bolt_agent presence")
					}
					response := []byte{0xb1, 0x70, 0xa3, 0x86, 's', 'e', 'r', 'v', 'e', 'r', 0x8c, 'N', 'e', 'o', '4', 'j', '/', '5', '.', '2', '6', '.', '0', 0x8d, 'c', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', '_', 'i', 'd', 0x86, 'b', 'o', 'l', 't', '-', '7', 0x85, 'h', 'i', 'n', 't', 's', 0xa1, 0x81, 'x', 1}
					// An initial NOOP and two chunks exercise bounded message assembly.
					frame := []byte{0, 0, 0, 2, 0xb1, 0x70, 0, byte(len(response) - 2)}
					frame = append(frame, response[2:]...)
					frame = append(frame, 0, 0)
					_, err = conn.Write(frame)
					return err
				}
				scripts := []func(net.Conn) error{script}
				if version[0] == 1 {
					scripts = append([]func(net.Conn) error{nativeDiscoveryRespond("bolt", []byte{0, 0, 0, 0})}, scripts...)
				}
				port := nativeDiscoveryListener(t, secure, scripts...)
				var probe nativeDiscoveryProbe = Neo4jFingerprinter{}
				if secure {
					probe = Neo4jTLSFingerprinter{}
				}
				result, err := probe.Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
				if err != nil || result == nil {
					t.Fatalf("metadata discovery failed: %v", err)
				}
				metadata := result.Metadata.Generic.Metadata
				if result.Version == nil || *result.Version != "5.26.0" || metadata["server"] != "Neo4j/5.26.0" || metadata["connection_id"] != "bolt-7" || metadata["cpes"] != "[cpe:2.3:a:neo4j:neo4j:5.26.0:*:*:*:*:*:*:*]" {
					t.Fatalf("missing server metadata: %#v version=%v", metadata, result.Version)
				}
			})
		}
	}
}

func nativeDiscoveryReadBoltChunk(conn net.Conn) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n > 256 {
		return nil, fmt.Errorf("oversized HELLO")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	if header != [2]byte{} {
		return nil, fmt.Errorf("HELLO missing terminator")
	}
	return payload, nil
}

func TestNativeDiscoveryBoltMetadataBounds(t *testing.T) {
	cases := map[string][]byte{
		"truncated-string":   {0, 6, 0xb1, 0x70, 0xa1, 0xd2, 0xff, 0xff, 0, 0},
		"oversized-map":      {0, 7, 0xb1, 0x70, 0xda, 0x7f, 0xff, 0xff, 0xff, 0, 0},
		"unexpected-message": {0, 3, 0xb1, 0x71, 0xa0, 0, 0},
		"trailing-data":      {0, 4, 0xb1, 0x70, 0xa0, 1, 0, 0},
		"noop-flood":         make([]byte, 512),
		"auth-failure":       {0, 12, 0xb1, 0x7f, 0xa1, 0x84, 'c', 'o', 'd', 'e', 0x83, 'b', 'a', 'd', 0, 0},
	}
	for name, response := range cases {
		t.Run(name, func(t *testing.T) {
			port := nativeDiscoveryListener(t, false, func(conn net.Conn) error {
				if err := nativeDiscoveryReadRequest(conn, "bolt"); err != nil {
					return err
				}
				if _, err := conn.Write([]byte{0, 0, 1, 5}); err != nil {
					return err
				}
				if _, err := nativeDiscoveryReadBoltChunk(conn); err != nil {
					return err
				}
				_, _ = conn.Write(response)
				return nil
			})
			result, err := (Neo4jFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
			if err != nil || result == nil {
				t.Fatalf("lost negotiated service: %v", err)
			}
			if result.Version == nil || *result.Version != "" || result.Metadata.Generic.Metadata["cpes"] != "" {
				t.Fatal("fabricated server version")
			}
			if name == "auth-failure" && result.Metadata.Generic.Metadata["code"] != "bad" {
				t.Fatal("lost failure metadata")
			}
		})
	}
	for _, data := range [][]byte{
		{0xa2, 0x81, 'x', 1, 0x81, 'x', 2},
		{0xa1, 1, 1},
		{0x81, 0xff},
		{0x91, 0x91, 0x91, 0x91, 0x91, 0x91, 0x91, 0x91, 0x91, 0x91, 0},
	} {
		budget := 4096
		if _, err := nativeBoltValue(bytes.NewReader(data), 0, &budget); err == nil {
			t.Fatalf("accepted invalid PackStream: %x", data)
		}
	}
}

func TestNativeDiscoveryBoltMetadataCancellation(t *testing.T) {
	port := nativeDiscoveryListener(t, false, func(conn net.Conn) error {
		if err := nativeDiscoveryReadRequest(conn, "bolt"); err != nil {
			return err
		}
		if _, err := conn.Write([]byte{0, 0, 1, 5}); err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, conn)
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	result, err := (Neo4jFingerprinter{}).Detect(ctx, net.ParseIP("127.0.0.1"), port, "localhost", -1)
	if err != nil || result == nil || time.Since(start) > time.Second {
		t.Fatalf("optional metadata did not honor cancellation: %v", err)
	}
}
