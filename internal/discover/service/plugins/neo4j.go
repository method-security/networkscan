package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"unicode/utf8"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type Neo4jFingerprinter struct{}
type Neo4jTLSFingerprinter struct{}

func (Neo4jFingerprinter) Name() string           { return "neo4j" }
func (Neo4jTLSFingerprinter) Name() string        { return "neo4j" }
func (Neo4jFingerprinter) DefaultPorts() []int    { return []int{7687} }
func (Neo4jTLSFingerprinter) DefaultPorts() []int { return []int{7687} }
func (Neo4jFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeBolt(ctx, ip, port, host, timeout, false)
}
func (Neo4jTLSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeBolt(ctx, ip, port, host, timeout, true)
}

// The fixed handshake and version ranges are specified at
// https://neo4j.com/docs/bolt/current/bolt/handshake/ . No credentials are sent.
func detectNativeBolt(ctx context.Context, ip net.IP, port int, host string, timeout int, secure bool) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	transport := common.TransportTypeTcp
	for attempt := 0; attempt < 2; attempt++ {
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
		// Offer 5.0-5.8, 4.0-4.4, 3.0 and 2.0. Older servers get one retry.
		request := []byte{0x60, 0x60, 0xb0, 0x17, 0, 8, 8, 5, 0, 4, 4, 4, 0, 0, 0, 3, 0, 0, 0, 2}
		if attempt == 1 {
			request = []byte{0x60, 0x60, 0xb0, 0x17, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		}
		if _, err = conn.Write(request); err != nil {
			return nil, err
		}
		var selected [4]byte
		if _, err = io.ReadFull(conn, selected[:]); err != nil {
			return nil, err
		}
		if selected == [4]byte{} && attempt == 0 {
			_ = conn.Close()
			continue
		}
		major, minor := selected[3], selected[2]
		valid := selected[0] == 0 && selected[1] == 0
		if attempt == 0 {
			valid = valid && ((major == 5 && minor <= 8) || (major == 4 && minor <= 4) || ((major == 2 || major == 3) && minor == 0))
		} else {
			valid = valid && major == 1 && minor == 0
		}
		if !valid {
			return nil, fmt.Errorf("invalid or unoffered Bolt version")
		}
		metadata := map[string]string{"bolt_version": fmt.Sprintf("%d.%d", major, minor)}
		version := ""
		// Negotiation already establishes Bolt. Optional metadata failure must not
		// turn an auth-required server into a negative or invent a product version.
		if fields, e := nativeBoltHello(conn, major, minor); e == nil {
			for _, key := range []string{"server", "connection_id", "code", "message"} {
				if value, ok := fields[key].(string); ok {
					metadata[key] = value
				}
			}
			if strings.HasPrefix(metadata["server"], "Neo4j/") {
				version = strings.TrimPrefix(metadata["server"], "Neo4j/")
				if version != "" && strings.IndexFunc(version, func(r rune) bool {
					return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '.' || r == '-' || r == '_')
				}) == -1 {
					metadata["cpes"] = "[cpe:2.3:a:neo4j:neo4j:" + version + ":*:*:*:*:*:*:*]"
				}
			}
		}
		result := helpers.GenericResult(host, ip, port, transport, common.ProtocolTypeNeo4J, "neo4j", version, metadata)
		result.Tls = &secure
		return result, nil
	}
	return nil, fmt.Errorf("no supported Bolt version")
}

// HELLO/INIT and SUCCESS/FAILURE follow the Bolt message specification:
// https://neo4j.com/docs/bolt/current/bolt/message/ . Versions before 5.1
// receive scheme=none once; 5.1+ receive HELLO only, never LOGON.
func nativeBoltHello(conn net.Conn, major, minor byte) (map[string]interface{}, error) {
	text := func(s string) []byte {
		if len(s) < 16 {
			return append([]byte{0x80 | byte(len(s))}, s...)
		}
		return append([]byte{0xd0, byte(len(s))}, s...)
	}
	payload := []byte{0xb1, 1}
	if major <= 2 {
		payload[0] = 0xb2
		payload = append(payload, text("networkscan/1")...)
		payload = append(payload, 0xa1)
	} else {
		count := byte(1)
		if major < 5 || minor == 0 || minor >= 3 {
			count++
		}
		payload = append(payload, 0xa0|count)
		payload = append(payload, text("user_agent")...)
		payload = append(payload, text("networkscan/1")...)
	}
	if major < 5 || minor == 0 {
		payload = append(payload, text("scheme")...)
		payload = append(payload, text("none")...)
	} else if minor >= 3 {
		payload = append(payload, text("bolt_agent")...)
		payload = append(payload, 0xa1)
		payload = append(payload, text("product")...)
		payload = append(payload, text("networkscan/1")...)
	}
	frame := make([]byte, 2)
	binary.BigEndian.PutUint16(frame, uint16(len(payload)))
	frame = append(frame, payload...)
	frame = append(frame, 0, 0)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	var message []byte
	for chunks := 0; chunks < 256; chunks++ {
		var header [2]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(header[:]))
		if n == 0 {
			if len(message) == 0 {
				continue
			}
			if len(message) < 3 || message[0] != 0xb1 || (message[1] != 0x70 && message[1] != 0x7f) {
				return nil, fmt.Errorf("unexpected Bolt summary")
			}
			r := bytes.NewReader(message[2:])
			budget := 4096
			value, err := nativeBoltValue(r, 0, &budget)
			if err != nil {
				return nil, err
			}
			fields, ok := value.(map[string]interface{})
			if !ok || r.Len() != 0 {
				return nil, fmt.Errorf("invalid Bolt metadata")
			}
			return fields, nil
		}
		if len(message)+n > 65536 {
			return nil, fmt.Errorf("Bolt metadata exceeds limit")
		}
		start := len(message)
		message = append(message, make([]byte, n)...)
		if _, err := io.ReadFull(conn, message[start:]); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("too many Bolt chunks")
}

// Only PackStream metadata values are supported, never graph structures.
// https://neo4j.com/docs/bolt/current/packstream/ . The frame, recursion,
// collection counts and total decoded values each have independent limits.
func nativeBoltValue(r *bytes.Reader, depth int, budget *int) (interface{}, error) {
	if depth > 8 || *budget <= 0 {
		return nil, fmt.Errorf("Bolt metadata complexity exceeds limit")
	}
	*budget--
	marker, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if marker <= 0x7f || marker >= 0xf0 {
		return int64(int8(marker)), nil
	}
	if marker == 0xc0 {
		return nil, nil
	}
	if marker == 0xc2 || marker == 0xc3 {
		return marker == 0xc3, nil
	}
	if marker == 0xc1 || (marker >= 0xc8 && marker <= 0xcb) {
		width := 8
		if marker != 0xc1 {
			width = 1 << (marker - 0xc8)
		}
		var b [8]byte
		if _, err = io.ReadFull(r, b[:width]); err != nil {
			return nil, err
		}
		// Numeric hints are not emitted as service metadata.
		return nil, nil
	}
	kind, count := byte(0), uint32(0)
	switch marker & 0xf0 {
	case 0x80, 0x90, 0xa0:
		kind, count = marker&0xf0, uint32(marker&15)
	default:
		var width int
		switch marker {
		case 0xd0, 0xd1, 0xd2:
			kind, width = 0x80, 1<<(marker-0xd0)
		case 0xd4, 0xd5, 0xd6:
			kind, width = 0x90, 1<<(marker-0xd4)
		case 0xd8, 0xd9, 0xda:
			kind, width = 0xa0, 1<<(marker-0xd8)
		default:
			return nil, fmt.Errorf("unsupported Bolt metadata marker")
		}
		var b [4]byte
		if _, err = io.ReadFull(r, b[4-width:]); err != nil {
			return nil, err
		}
		count = binary.BigEndian.Uint32(b[:])
	}
	if uint64(count) > uint64(r.Len()) {
		return nil, io.ErrUnexpectedEOF
	}
	if kind == 0x80 {
		b := make([]byte, int(count))
		_, _ = io.ReadFull(r, b)
		if !utf8.Valid(b) {
			return nil, fmt.Errorf("invalid Bolt UTF-8")
		}
		return string(b), nil
	}
	if count > 1024 {
		return nil, fmt.Errorf("Bolt collection exceeds limit")
	}
	if kind == 0x90 {
		for i := uint32(0); i < count; i++ {
			if _, err = nativeBoltValue(r, depth+1, budget); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	fields := make(map[string]interface{}, int(count))
	for i := uint32(0); i < count; i++ {
		key, e := nativeBoltValue(r, depth+1, budget)
		if e != nil {
			return nil, e
		}
		name, ok := key.(string)
		if !ok {
			return nil, fmt.Errorf("non-string Bolt map key")
		}
		if _, exists := fields[name]; exists {
			return nil, fmt.Errorf("duplicate Bolt map key")
		}
		value, e := nativeBoltValue(r, depth+1, budget)
		if e != nil {
			return nil, e
		}
		fields[name] = value
	}
	return fields, nil
}
