package plugins

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"unicode/utf8"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type JDWPFingerprinter struct{}

func (JDWPFingerprinter) Name() string { return "jdwp" }
func (JDWPFingerprinter) DefaultPorts() []int {
	return []int{3999, 5000, 5005, 8000, 8453, 8787, 8788, 9001, 18000}
}

// Oracle's JDWP specification defines the handshake and VirtualMachine.Version (1/1).
func (JDWPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	const handshake = "JDWP-Handshake"
	if _, err = io.WriteString(conn, handshake); err != nil {
		return nil, err
	}
	hello := make([]byte, len(handshake))
	if _, err = io.ReadFull(conn, hello); err != nil {
		return nil, err
	}
	if string(hello) != handshake {
		return nil, fmt.Errorf("invalid JDWP handshake")
	}
	request := []byte{0, 0, 0, 11, 0, 0, 0, 0, 0, 1, 1}
	if _, err = rand.Read(request[4:8]); err != nil {
		return nil, err
	}
	if _, err = conn.Write(request); err != nil {
		return nil, err
	}
	// A VMStart event can precede the Version reply. Bound both packets and bytes.
	for packets := 0; packets < 16; packets++ {
		header := make([]byte, 11)
		if _, err = io.ReadFull(conn, header); err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(header)
		if n < 11 || n > 65536 {
			return nil, fmt.Errorf("invalid JDWP packet length")
		}
		body := make([]byte, int(n)-11)
		if _, err = io.ReadFull(conn, body); err != nil {
			return nil, err
		}
		if header[8] == 0 && header[9] == 64 && header[10] == 100 {
			if len(body) < 5 || body[0] > 2 {
				return nil, fmt.Errorf("invalid JDWP event")
			}
			continue
		}
		if header[8] != 0x80 || !bytes.Equal(header[4:8], request[4:8]) || binary.BigEndian.Uint16(header[9:]) != 0 {
			return nil, fmt.Errorf("invalid JDWP Version reply")
		}
		metadata, err := jdwpDiscoveryVersion(body)
		if err != nil {
			return nil, err
		}
		return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeJdwp, "JDWP", metadata["VMVersion"], metadata), nil
	}
	return nil, fmt.Errorf("JDWP Version reply not received within packet limit")
}

func jdwpDiscoveryVersion(body []byte) (map[string]string, error) {
	metadata := make(map[string]string)
	for _, key := range []string{"description", "jdwpMajor", "jdwpMinor", "VMVersion", "VMName"} {
		if len(body) < 4 {
			return nil, fmt.Errorf("truncated JDWP Version")
		}
		n := binary.BigEndian.Uint32(body)
		body = body[4:]
		if key == "jdwpMajor" || key == "jdwpMinor" {
			if n > 0x7fffffff {
				return nil, fmt.Errorf("negative JDWP version")
			}
			metadata[key] = strconv.FormatUint(uint64(n), 10)
			continue
		}
		if uint64(n) > uint64(len(body)) || !utf8.Valid(body[:n]) {
			return nil, fmt.Errorf("invalid JDWP string")
		}
		metadata[key] = string(body[:n])
		body = body[n:]
	}
	if len(body) != 0 {
		return nil, fmt.Errorf("trailing JDWP Version data")
	}
	return metadata, nil
}
