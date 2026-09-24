package plugins

import (
	"context"
	"fmt"
	"net"
	"unicode/utf8"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
)

type MilvusFingerprinter struct{}

func (MilvusFingerprinter) Name() string        { return "milvus" }
func (MilvusFingerprinter) DefaultPorts() []int { return []int{19530} }
func (MilvusFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	for _, secure := range []bool{false, true} {
		cc, err := productGRPC(ctx, ip, port, host, timeout, secure)
		if err != nil {
			continue
		}
		var request, response []byte
		err = cc.Invoke(ctx, "/milvus.proto.milvus.MilvusService/GetVersion", &request, &response, grpc.ForceCodec(milvusVersionCodec{}))
		_ = cc.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			continue
		}
		version, ok := milvusVersion(response)
		if ok {
			return productHTTPResult(host, ip, port, secure, common.ProtocolTypeMilvus, "milvus", version, nil, map[string]string{"rpcService": "milvus.proto.milvus.MilvusService", "discovery": "grpc-version"}), nil
		}
	}
	return nil, nil
}

// Only GetVersion's empty request and bounded response pass through this codec.
// Field interpretation below follows milvus-proto's milvus.proto/common.proto.
type milvusVersionCodec struct{}

func (milvusVersionCodec) Name() string { return "proto" }
func (milvusVersionCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.(*[]byte)
	if !ok {
		return nil, fmt.Errorf("unexpected Milvus message %T", v)
	}
	return *b, nil
}
func (milvusVersionCodec) Unmarshal(b []byte, v any) error {
	dst, ok := v.(*[]byte)
	if !ok || len(b) > productBodyLimit {
		return fmt.Errorf("invalid Milvus message")
	}
	*dst = append((*dst)[:0], b...)
	return nil
}

func milvusVersion(b []byte) (string, bool) {
	var version string
	statusSeen := false
	for len(b) > 0 {
		number, kind, n := protowire.ConsumeTag(b)
		if n < 0 {
			return "", false
		}
		b = b[n:]
		if number == 1 || number == 2 {
			if kind != protowire.BytesType {
				return "", false
			}
			value, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return "", false
			}
			b = b[n:]
			if number == 1 {
				if !milvusSuccess(value) {
					return "", false
				}
				statusSeen = true
			} else {
				version = string(value)
			}
		} else {
			n := protowire.ConsumeFieldValue(number, kind, b)
			if n < 0 {
				return "", false
			}
			b = b[n:]
		}
	}
	return version, statusSeen && version != "" && len(version) <= 256 && utf8.ValidString(version)
}

func milvusSuccess(b []byte) bool {
	for len(b) > 0 {
		number, kind, n := protowire.ConsumeTag(b)
		if n < 0 {
			return false
		}
		b = b[n:]
		if number == 1 || number == 3 {
			if kind != protowire.VarintType {
				return false
			}
			code, n := protowire.ConsumeVarint(b)
			if n < 0 || code != 0 {
				return false
			}
			b = b[n:]
		} else {
			n := protowire.ConsumeFieldValue(number, kind, b)
			if n < 0 {
				return false
			}
			b = b[n:]
		}
	}
	return true
}
