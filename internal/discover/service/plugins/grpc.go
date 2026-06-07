// Package plugins provides gRPC service fingerprinting by issuing a Server-Reflection
// ListServices request.  It avoids HTTP/2 false-positives because only a
// genuine gRPC server can speak the reflection protocol or return a proper
// gRPC UNIMPLEMENTED status.
package plugins

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	reflectionpb "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
)

/* -------------------------------------------------------------------------- */
/*  Exported fingerprinter                                                    */
/* -------------------------------------------------------------------------- */

type GrpcFingerprinter struct{}

func (GrpcFingerprinter) Name() string { return "grpc" }

func (GrpcFingerprinter) DefaultPorts() []int { return []int{} }

func (GrpcFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Create a context with timeout
	timeoutDuration := serviceTimeout(timeout)
	timeoutCtx, cancel := serviceContext(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	/* ---- try plaintext first --------------------------------------------- */
	conn, tlsUsed, err := dial(timeoutCtx, addr, timeoutDuration, false)
	if err != nil {
		/* ---- fallback to opportunistic TLS -------------------------------- */
		conn, tlsUsed, err = dial(timeoutCtx, addr, timeoutDuration, true)
		if err != nil {
			return nil, nil // neither path worked → not gRPC
		}
	}
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	/* ---- Server-reflection ListServices ---------------------------------- */
	rctx, cancel := serviceContextDuration(timeoutCtx, timeoutDuration/2)
	defer cancel()

	refClient, err := reflectionpb.NewServerReflectionClient(conn).ServerReflectionInfo(rctx)
	if err != nil {
		return nil, nil // reflection service not reachable → not gRPC
	}
	if err := refClient.Send(&reflectionpb.ServerReflectionRequest{
		MessageRequest: &reflectionpb.ServerReflectionRequest_ListServices{
			ListServices: "*",
		},
	}); err != nil {
		return nil, nil // send failed
	}

	resp, err := refClient.Recv()

	/* ---- evaluate outcome ------------------------------------------------- */
	switch {
	//   1. Successful list → definite gRPC
	case err == nil && resp.GetListServicesResponse() != nil:
		return buildResult(host, ip, port, tlsUsed, "LIST_OK"), nil

	//   2. gRPC status UNIMPLEMENTED → still gRPC (reflection disabled)
	case err != nil && status.Code(err) == codes.Unimplemented:
		return buildResult(host, ip, port, tlsUsed, "UNIMPLEMENTED"), nil

	//   otherwise → not gRPC
	default:
		return nil, nil
	}
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

func dial(ctx context.Context, addr string, to time.Duration, useTLS bool) (*grpc.ClientConn, bool, error) {
	dctx, cancel := serviceContextDuration(ctx, to)
	defer cancel()

	opts := []grpc.DialOption{grpc.WithBlock()}
	if useTLS {
		opts = append(opts,
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.DialContext(dctx, addr, opts...)
	if err != nil {
		return nil, false, err
	}
	return conn, useTLS, nil
}

func buildResult(host string, ip net.IP, port int, tlsUsed bool, statusStr string) *discoverfern.ServiceDetails {
	transport := "TCP"
	if tlsUsed {
		transport = "TCPTLS"
	}

	// reflectionSupported is true if server returned LIST_OK (reflection enabled)
	reflectionSupported := statusStr == "LIST_OK"

	metadata := &protocol.GrpcServerInfo{
		ReflectionSupported: reflectionSupported,
	}

	return &discoverfern.ServiceDetails{
		Host:    host,
		Ip:      ip.String(),
		Port:    port,
		Tls:     tlsUsed,
		Version: nil,
		Transport: func() common.TransportType {
			if transport == "TCPTLS" {
				return common.TransportTypeTcptls
			}
			return common.TransportTypeTcp
		}(),
		Protocol: common.ProtocolTypeGrpc,
		Metadata: &discoverfern.ServiceMetadata{Grpc: metadata},
	}
}
