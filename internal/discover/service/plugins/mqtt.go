package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"unicode/utf8"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type MQTT3Fingerprinter struct{}
type MQTT3TLSFingerprinter struct{}
type MQTT5Fingerprinter struct{}
type MQTT5TLSFingerprinter struct{}

func (MQTT3Fingerprinter) Name() string           { return "mqtt3" }
func (MQTT3TLSFingerprinter) Name() string        { return "mqtt3tls" }
func (MQTT5Fingerprinter) Name() string           { return "mqtt5" }
func (MQTT5TLSFingerprinter) Name() string        { return "mqtt5tls" }
func (MQTT3Fingerprinter) DefaultPorts() []int    { return []int{1883} }
func (MQTT3TLSFingerprinter) DefaultPorts() []int { return []int{8883} }
func (MQTT5Fingerprinter) DefaultPorts() []int    { return []int{1883} }
func (MQTT5TLSFingerprinter) DefaultPorts() []int { return []int{8883} }
func (MQTT3Fingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeMQTT(ctx, ip, port, host, timeout, false, false)
}
func (MQTT3TLSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeMQTT(ctx, ip, port, host, timeout, true, false)
}
func (MQTT5Fingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeMQTT(ctx, ip, port, host, timeout, false, true)
}
func (MQTT5TLSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeMQTT(ctx, ip, port, host, timeout, true, true)
}

// CONNECT/CONNACK: OASIS MQTT 3.1.1 and 5.0, sections 3.1 and 3.2.
func detectNativeMQTT(ctx context.Context, ip net.IP, port int, host string, timeout int, secure, v5 bool) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	transport := common.TransportTypeTcp
	if secure {
		upgraded, e := helpers.UpgradeTLS(ctx, conn, host)
		if e != nil {
			return nil, e
		}
		conn = upgraded
	}
	// Clean session/start and no credentials, will, subscriptions or publications.
	body := []byte{0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 10}
	protocol, name, version := common.ProtocolTypeMqtt3, "mqtt3", "3.1.1"
	if v5 {
		body[6] = 5
		body = append(body, 0)
		protocol, name, version = common.ProtocolTypeMqtt5, "mqtt5", "5.0"
	}
	// A zero-length client ID requests a server-assigned ID with clean start.
	body = append(body, 0, 0)
	if _, err = conn.Write(append([]byte{0x10, byte(len(body))}, body...)); err != nil {
		return nil, err
	}
	var header [1]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 0x20 {
		return nil, fmt.Errorf("not MQTT CONNACK")
	}
	n, err := nativeMQTTLength(conn)
	if err != nil {
		return nil, err
	}
	if n < 2 || n > 65536 || (!v5 && n != 2) {
		return nil, fmt.Errorf("invalid CONNACK length")
	}
	data := make([]byte, n)
	if _, err = io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	// Clean start requires Session Present=0, even on successful connection.
	if data[0] != 0 {
		return nil, fmt.Errorf("unexpected CONNACK session flags")
	}
	code := data[1]
	metadata := map[string]string{"return_code": strconv.Itoa(int(code))}
	if v5 {
		switch code {
		case 0, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8c, 0x90, 0x95, 0x97, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9f:
		default:
			return nil, fmt.Errorf("invalid MQTT 5 CONNACK reason")
		}
		if err = nativeMQTTProperties(data[2:], metadata); err != nil {
			return nil, err
		}
	} else if code > 5 {
		return nil, fmt.Errorf("invalid MQTT 3 CONNACK return code")
	}
	result := helpers.GenericResult(host, ip, port, transport, protocol, name, version, metadata)
	result.Tls = &secure
	return result, nil
}

func nativeMQTTLength(r io.Reader) (int, error) {
	n := 0
	for i := 0; i < 4; i++ {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		n |= int(b[0]&127) << (7 * i)
		if b[0]&128 == 0 {
			if i > 0 && b[0] == 0 {
				return 0, fmt.Errorf("nonminimal MQTT length")
			}
			return n, nil
		}
	}
	return 0, fmt.Errorf("MQTT length exceeds four bytes")
}

func nativeMQTTProperties(data []byte, metadata map[string]string) error {
	r := bytes.NewReader(data)
	n, err := nativeMQTTLength(r)
	if err != nil || n != r.Len() {
		return fmt.Errorf("invalid MQTT property length")
	}
	seen := map[byte]bool{}
	readString := func() (string, error) {
		var n uint16
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return "", err
		}
		if int(n) > r.Len() {
			return "", io.ErrUnexpectedEOF
		}
		b := make([]byte, n)
		_, _ = io.ReadFull(r, b)
		if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
			return "", fmt.Errorf("invalid MQTT UTF-8")
		}
		return string(b), nil
	}
	for r.Len() > 0 {
		id, _ := r.ReadByte()
		if seen[id] && id != 0x26 {
			return fmt.Errorf("duplicate MQTT property")
		}
		seen[id] = true
		switch id {
		case 0x12, 0x15, 0x1a, 0x1c, 0x1f, 0x26:
			s, e := readString()
			if e != nil {
				return e
			}
			if id == 0x26 {
				if _, e = readString(); e != nil {
					return e
				}
			}
			if id == 0x1f {
				metadata["reason_string"] = s
			}
			if id == 0x12 {
				metadata["assigned_client_identifier"] = s
			}
		case 0x16:
			var n uint16
			if e := binary.Read(r, binary.BigEndian, &n); e != nil {
				return e
			}
			if int(n) > r.Len() {
				return io.ErrUnexpectedEOF
			}
			_, _ = r.Seek(int64(n), io.SeekCurrent)
		case 0x11, 0x27:
			var n uint32
			if e := binary.Read(r, binary.BigEndian, &n); e != nil {
				return e
			}
			if id == 0x27 && n == 0 {
				return fmt.Errorf("zero maximum packet size")
			}
		case 0x13, 0x21, 0x22:
			var n uint16
			if e := binary.Read(r, binary.BigEndian, &n); e != nil {
				return e
			}
			if id == 0x21 && n == 0 {
				return fmt.Errorf("zero receive maximum")
			}
		case 0x24, 0x25, 0x28, 0x29, 0x2a:
			b, e := r.ReadByte()
			if e != nil {
				return e
			}
			if b > 1 {
				return fmt.Errorf("invalid MQTT boolean property")
			}
		default:
			return fmt.Errorf("invalid CONNACK property %x", id)
		}
	}
	if seen[0x16] && !seen[0x15] {
		return fmt.Errorf("authentication data without method")
	}
	return nil
}
