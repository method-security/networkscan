package plugins

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"strconv"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	reflection "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
)

type ChromaDBFingerprinter struct{}
type ChromaDBTLSFingerprinter struct{}

func (ChromaDBFingerprinter) Name() string           { return "chromadb" }
func (ChromaDBTLSFingerprinter) Name() string        { return "chromadb" }
func (ChromaDBFingerprinter) DefaultPorts() []int    { return []int{8000} }
func (ChromaDBTLSFingerprinter) DefaultPorts() []int { return []int{8000} }
func (ChromaDBFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return discoverChromaDB(ctx, ip, port, host, timeout, false)
}
func (ChromaDBTLSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return discoverChromaDB(ctx, ip, port, host, timeout, true)
}

func discoverChromaDB(ctx context.Context, ip net.IP, port int, host string, timeout int, secure bool) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	p := newProductHTTP(ip, port, host, timeout, secure)
	defer p.transport.CloseIdleConnections()
	for _, prefix := range []string{"/api/v2", "/api/v1"} {
		r, b, err := p.get(ctx, prefix+"/heartbeat")
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			break
		}
		var heartbeat struct {
			Nanoseconds int64 `json:"nanosecond heartbeat"`
		}
		if r.StatusCode != 200 || json.Unmarshal(b, &heartbeat) != nil || heartbeat.Nanoseconds <= 0 {
			continue
		}
		// The uniquely named heartbeat is positive evidence; version is optional.
		version := ""
		if vr, vb, err := p.get(ctx, prefix+"/version"); err == nil && vr.StatusCode == 200 {
			if json.Unmarshal(vb, &version) != nil {
				version = productString(productJSON(vb), "version")
			}
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return productHTTPResult(host, ip, port, secure, common.ProtocolTypeChromadb, "chromadb", version, r, map[string]string{"apiPath": prefix, "heartbeat": strconv.FormatInt(heartbeat.Nanoseconds, 10)}), nil
	}
	cc, err := productGRPC(ctx, ip, port, host, timeout, secure)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cc.Close() }()
	service, err := chromaReflectedService(ctx, cc)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || service == "" {
		return nil, nil
	}
	return productHTTPResult(host, ip, port, secure, common.ProtocolTypeChromadb, "chromadb", "", nil, map[string]string{"rpcService": service, "discovery": "grpc-reflection"}), nil
}

// gRPC owns HTTP/2 framing and message limits; the scanner owns endpoint dialing.
func productGRPC(ctx context.Context, ip net.IP, port int, host string, timeout int, secure bool) (*grpc.ClientConn, error) {
	if host == "" {
		host = ip.String()
	}
	creds := insecure.NewCredentials()
	if secure {
		creds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: true, ServerName: host})
	} //nolint:gosec
	return grpc.NewClient("passthrough:///"+net.JoinHostPort(ip.String(), strconv.Itoa(port)),
		grpc.WithTransportCredentials(creds), grpc.WithAuthority(host),
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			// Dial's cancellation watcher must use the attempt context: gRPC
			// cancels its temporary dial context after taking the connection.
			return helpers.TCPConn(ctx, ip, port, timeout)
		}), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(productBodyLimit)), grpc.WithMaxHeaderListSize(64<<10))
}

func chromaReflectedService(ctx context.Context, cc *grpc.ClientConn) (string, error) {
	s, err := reflection.NewServerReflectionClient(cc).ServerReflectionInfo(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = s.CloseSend() }()
	if err := s.Send(&reflection.ServerReflectionRequest{MessageRequest: &reflection.ServerReflectionRequest_ListServices{ListServices: ""}}); err != nil {
		return "", err
	}
	r, err := s.Recv()
	if err != nil {
		return "", err
	}
	for _, service := range r.GetListServicesResponse().GetService() {
		switch service.Name {
		case "chroma.SysDB", "chroma.MetadataReader", "chroma.VectorReader", "chroma.QueryExecutor", "chroma.LogService":
			return service.Name, nil
		}
	}
	return "", nil
}
