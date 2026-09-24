package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type FirebirdFingerprinter struct{}

func (FirebirdFingerprinter) Name() string        { return "firebird" }
func (FirebirdFingerprinter) DefaultPorts() []int { return []int{3050} }

// Only op_connect is sent; no database/service attachment or password exchange.
// https://firebirdsql.org/file/documentation/html/en/firebirddocs/wireprotocol/firebird-wire-protocol.html
func (FirebirdFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	var request []byte
	// Connect v3, generic architecture, empty target, ten supported protocols, empty identity.
	for _, v := range []uint32{1, 0, 3, 1, 0, 10, 0} {
		request = binary.BigEndian.AppendUint32(request, v)
	}
	for version := uint32(10); version <= 19; version++ {
		wire := version
		if version > 10 {
			wire |= 0x8000
		}
		for _, v := range []uint32{wire, 1, 3, 5, version - 9} {
			request = binary.BigEndian.AppendUint32(request, v)
		}
	}
	if _, err = conn.Write(request); err != nil {
		return nil, err
	}
	meta, err := firebirdAccept(conn)
	if err != nil {
		return nil, err
	}
	return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeFirebird, "firebird", "", meta), nil
}

func firebirdAccept(r io.Reader) (map[string]string, error) {
	bad := fmt.Errorf("invalid Firebird connect response")
	var h [16]byte
	for count := 0; ; count++ {
		if count == 8 {
			return nil, bad
		}
		if _, err := io.ReadFull(r, h[:4]); err != nil {
			return nil, err
		}
		if binary.BigEndian.Uint32(h[:4]) != 71 {
			break
		}
	}
	op := binary.BigEndian.Uint32(h[:4])
	if op == 9 {
		return firebirdConnectError(r)
	}
	if op != 3 && op != 94 && op != 98 {
		return nil, bad
	}
	if _, err := io.ReadFull(r, h[4:]); err != nil {
		return nil, err
	}
	wire := binary.BigEndian.Uint32(h[4:8])
	version := wire & 0x7fff
	arch := binary.BigEndian.Uint32(h[8:12])
	kind := binary.BigEndian.Uint32(h[12:])
	if version < 10 || version > 19 || wire & ^uint32(0x801f) != 0 || version > 10 && wire&0x8000 == 0 || arch != 1 || kind < 3 || kind > 5 {
		return nil, bad
	}
	if op != 3 && version < 13 {
		return nil, bad
	}
	meta := map[string]string{"protocol_version": strconv.FormatUint(uint64(wire), 10),
		"negotiatedProtocol": strconv.FormatUint(uint64(version), 10),
		"cpes":               "[cpe:2.3:a:firebirdsql:firebird:*:*:*:*:*:*:*:*]"}
	if op != 3 {
		if _, err := firebirdBuffer(r); err != nil {
			return nil, err
		}
		plugin, err := firebirdBuffer(r)
		if err != nil {
			return nil, err
		}
		var flag [4]byte
		if _, err = io.ReadFull(r, flag[:]); err != nil {
			return nil, err
		}
		authenticated := binary.BigEndian.Uint32(flag[:])
		if authenticated > 1 {
			return nil, bad
		}
		if _, err = firebirdBuffer(r); err != nil {
			return nil, err
		}
		meta["authRequired"] = strconv.FormatBool(authenticated == 0)
		meta["authPlugin"] = string(plugin)
	}
	return meta, nil
}

// Generic response status vectors are typed XDR values, not a byte signature.
func firebirdConnectError(r io.Reader) (map[string]string, error) {
	bad := fmt.Errorf("invalid Firebird error response")
	var object [12]byte
	if _, err := io.ReadFull(r, object[:]); err != nil {
		return nil, err
	}
	if _, err := firebirdBuffer(r); err != nil {
		return nil, err
	}
	var first uint32
	for i := 0; i < 64; i++ {
		var word [4]byte
		if _, err := io.ReadFull(r, word[:]); err != nil {
			return nil, err
		}
		tag := binary.BigEndian.Uint32(word[:])
		if i == 0 && tag != 1 {
			return nil, bad
		}
		switch tag {
		case 0:
			if first < 335544321 || first > 335545999 {
				return nil, bad
			}
			meta := map[string]string{"errorCode": strconv.FormatUint(uint64(first), 10), "cpes": "[cpe:2.3:a:firebirdsql:firebird:*:*:*:*:*:*:*:*]"}
			if first == 335544472 {
				meta["authRequired"] = "true"
			}
			return meta, nil
		case 1, 4, 6, 7, 8, 9, 10, 11, 15, 16, 17, 18:
			if _, err := io.ReadFull(r, word[:]); err != nil {
				return nil, err
			}
			if i == 0 {
				first = binary.BigEndian.Uint32(word[:])
			}
		case 2, 5, 19:
			if _, err := firebirdBuffer(r); err != nil {
				return nil, err
			}
		default:
			return nil, bad
		}
	}
	return nil, bad
}

func firebirdBuffer(r io.Reader) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n > 16384 {
		return nil, fmt.Errorf("Firebird XDR buffer too large")
	}
	b := make([]byte, (int(n)+3)&^3)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b[:n], nil
}
