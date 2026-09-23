package plugins

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type PcomFingerprinter struct{}

func (PcomFingerprinter) Name() string { return "pcom" }

func (PcomFingerprinter) DefaultPorts() []int { return []int{20256} }

func (PcomFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	var lastErr error
	// Native Ethernet framing first, then raw ASCII for serial-over-TCP bridges.
	for _, framed := range []bool{true, false} {
		attemptCtx := ctx
		stop := func() {}
		if deadline, ok := ctx.Deadline(); ok && framed {
			attemptCtx, stop = context.WithTimeout(ctx, time.Until(deadline)/2)
		}
		lastErr = exchangePcomID(attemptCtx, ip, port, framed)
		stop()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if lastErr == nil {
			// ID layouts vary by controller; do not infer model/version from unit IDs.
			return &discoverfern.ServiceDetails{
				Host: host, Ip: ip.String(), Port: port,
				Transport: common.TransportTypeTcp, Protocol: common.ProtocolTypePcom,
			}, nil
		}
	}
	return nil, fmt.Errorf("no valid PCOM ID response: %w", lastErr)
}

func exchangePcomID(ctx context.Context, ip net.IP, port int, framed bool) error {
	conn, err := helpers.TCPConn(ctx, ip, port, -1)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	// Unit 00 addresses the directly connected PLC. ED is its ID request checksum.
	request := []byte("/00IDED\r")
	header := make([]byte, 6)
	if framed {
		if _, err := rand.Read(header[:2]); err != nil {
			return err
		}
		header[2] = 101
		binary.LittleEndian.PutUint16(header[4:], uint16(len(request)))
		request = append(header, request...)
	}
	if _, err := io.Copy(conn, bytes.NewReader(request)); err != nil {
		return err
	}
	response, err := readPcomID(conn, header, framed)
	if err != nil {
		return err
	}
	return validatePcomID(response)
}

func readPcomID(r io.Reader, requestHeader []byte, framed bool) ([]byte, error) {
	const maxReply = 1024
	if !framed {
		return bufio.NewReaderSize(io.LimitReader(r, maxReply), maxReply).ReadSlice('\r')
	}
	header := make([]byte, 6)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if !bytes.Equal(header[:4], requestHeader[:4]) {
		return nil, fmt.Errorf("PCOM transaction or protocol mismatch")
	}
	n := int(binary.LittleEndian.Uint16(header[4:]))
	if n < 10 || n > maxReply {
		return nil, fmt.Errorf("invalid PCOM ID length: %d", n)
	}
	body := make([]byte, n)
	_, err := io.ReadFull(r, body)
	return body, err
}

func validatePcomID(b []byte) error {
	if len(b) < 10 || !bytes.HasPrefix(b, []byte("/A00ID")) || b[len(b)-1] != '\r' {
		return fmt.Errorf("invalid PCOM ID response framing")
	}
	dataEnd := len(b) - 3
	if strings.TrimSpace(string(b[6:dataEnd])) == "" {
		return fmt.Errorf("empty PCOM identity")
	}
	var checksum byte
	// The response start marker is /A; neither byte participates in the checksum.
	for _, c := range b[2:dataEnd] {
		if c < 32 || c > 126 {
			return fmt.Errorf("non-ASCII PCOM identity")
		}
		checksum += c
	}
	var expected [1]byte
	if _, err := hex.Decode(expected[:], b[dataEnd:dataEnd+2]); err != nil || expected[0] != checksum {
		return fmt.Errorf("invalid PCOM ID checksum")
	}
	return nil
}
