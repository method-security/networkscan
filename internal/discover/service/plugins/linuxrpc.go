package plugins

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type RPCFingerprinter struct{}

func (RPCFingerprinter) Name() string        { return "RPC" }
func (RPCFingerprinter) DefaultPorts() []int { return []int{111} }

// RFC 5531 record marking and RFC 1833 rpcbind DUMP, using AUTH_NONE.
func (RPCFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	request := make([]byte, 44)
	for i, word := range []uint32{0x80000028, 0, 0, 2, 100000, 4, 4, 0, 0, 0, 0} {
		binary.BigEndian.PutUint32(request[i*4:], word)
	}
	if _, err = rand.Read(request[4:8]); err != nil {
		return nil, err
	}
	for version := uint32(4); version >= 3; version-- {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		binary.BigEndian.PutUint32(request[20:], version)
		xid := binary.BigEndian.Uint32(request[4:8])
		if _, err = conn.Write(request); err != nil {
			return nil, err
		}
		record, err := rpcDiscoveryRecord(conn)
		if err != nil {
			return nil, err
		}
		body, status, err := rpcDiscoveryReply(record, xid)
		if err != nil {
			return nil, err
		}
		if status == 2 && version == 4 && len(body) == 8 {
			low, high := binary.BigEndian.Uint32(body), binary.BigEndian.Uint32(body[4:])
			if low <= 3 && high == 3 {
				// Retry only an advertised v3 after PROG_MISMATCH, with a distinct XID.
				binary.BigEndian.PutUint32(request[4:], xid+1)
				continue
			}
		}
		if status != 0 {
			return nil, fmt.Errorf("RPC DUMP v%d not accepted", version)
		}
		entries, err := rpcDiscoveryEntries(body)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(entries)
		if err != nil {
			return nil, err
		}
		return helpers.GenericResult(host, ip, port, common.TransportTypeTcp, common.ProtocolTypeRpc, "RPC", "", map[string]string{
			"entries": string(encoded), "rpcbindVersion": strconv.FormatUint(uint64(version), 10),
		}), nil
	}
	return nil, fmt.Errorf("RPC DUMP version negotiation exhausted")
}

func rpcDiscoveryRecord(r io.Reader) ([]byte, error) {
	var record []byte
	for fragments := 0; fragments < 32; fragments++ {
		var marker uint32
		if err := binary.Read(r, binary.BigEndian, &marker); err != nil {
			return nil, err
		}
		n := int(marker & 0x7fffffff)
		if n > 262144-len(record) {
			return nil, fmt.Errorf("RPC record exceeds discovery limit")
		}
		start := len(record)
		record = append(record, make([]byte, n)...)
		if _, err := io.ReadFull(r, record[start:]); err != nil {
			return nil, err
		}
		if marker&0x80000000 != 0 {
			return record, nil
		}
	}
	return nil, fmt.Errorf("too many RPC fragments")
}

type rpcDiscoveryEntry struct {
	Program  uint32 `json:"program"`
	Version  uint32 `json:"version"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Owner    string `json:"owner"`
}

func rpcDiscoveryReply(record []byte, xid uint32) ([]byte, uint32, error) {
	if len(record) < 24 || binary.BigEndian.Uint32(record) != xid || binary.BigEndian.Uint32(record[4:]) != 1 || binary.BigEndian.Uint32(record[8:]) != 0 {
		return nil, 0, fmt.Errorf("invalid RPC reply identity/status")
	}
	// opaque_auth is bounded to 400 bytes by RFC 5531, including unknown flavors.
	verifierLen := binary.BigEndian.Uint32(record[16:])
	if verifierLen > 400 || (binary.BigEndian.Uint32(record[12:]) == 0 && verifierLen != 0) {
		return nil, 0, fmt.Errorf("invalid RPC verifier")
	}
	offset := 20 + int((verifierLen+3)&^3)
	if offset+4 > len(record) {
		return nil, 0, fmt.Errorf("truncated RPC verifier/status")
	}
	for _, pad := range record[20+int(verifierLen) : offset] {
		if pad != 0 {
			return nil, 0, fmt.Errorf("invalid RPC verifier padding")
		}
	}
	return record[offset+4:], binary.BigEndian.Uint32(record[offset:]), nil
}

func rpcDiscoveryEntries(body []byte) ([]rpcDiscoveryEntry, error) {
	r := bytes.NewReader(body)
	entries := make([]rpcDiscoveryEntry, 0)
	for {
		var present uint32
		if err := binary.Read(r, binary.BigEndian, &present); err != nil {
			return nil, err
		}
		if present == 0 {
			if r.Len() != 0 {
				return nil, fmt.Errorf("trailing RPC DUMP data")
			}
			return entries, nil
		}
		if present != 1 || len(entries) >= 512 {
			return nil, fmt.Errorf("invalid or oversized RPC DUMP list")
		}
		var entry rpcDiscoveryEntry
		if err := binary.Read(r, binary.BigEndian, &entry.Program); err != nil {
			return nil, err
		}
		if err := binary.Read(r, binary.BigEndian, &entry.Version); err != nil {
			return nil, err
		}
		for _, field := range []*string{&entry.Protocol, &entry.Address, &entry.Owner} {
			var n uint32
			if err := binary.Read(r, binary.BigEndian, &n); err != nil {
				return nil, err
			}
			if n > 4096 || uint64((n+3)&^3) > uint64(r.Len()) {
				return nil, fmt.Errorf("invalid RPC string length")
			}
			value := make([]byte, (n+3)&^3)
			if _, err := io.ReadFull(r, value); err != nil {
				return nil, err
			}
			for _, pad := range value[n:] {
				if pad != 0 {
					return nil, fmt.Errorf("invalid RPC XDR padding")
				}
			}
			*field = string(value[:n])
		}
		entries = append(entries, entry)
	}
}
