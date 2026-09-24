package plugins

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type EchoFingerprinter struct{}

func (EchoFingerprinter) Name() string        { return "echo" }
func (EchoFingerprinter) DefaultPorts() []int { return []int{7} }

// RFC 862: a TCP echo service returns the exact octets received.
func (EchoFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	var nonce [24]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	probe := []byte("networkscan-echo:" + hex.EncodeToString(nonce[:]) + "\r\n")
	if _, err = conn.Write(probe); err != nil {
		return nil, err
	}
	response := make([]byte, len(probe))
	if _, err = io.ReadFull(conn, response); err != nil {
		return nil, err
	}
	if !bytes.Equal(response, probe) {
		return nil, fmt.Errorf("not TCP echo")
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeEcho, "ECHO", "", nil), nil
}
