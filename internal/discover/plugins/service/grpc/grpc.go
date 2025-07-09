// Package grpc fingerprints gRPC services by issuing a Server-Reflection
// ListServices request.  It avoids HTTP/2 false-positives because only a
// genuine gRPC server can speak the reflection protocol or return a proper
// gRPC UNIMPLEMENTED status.
package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	reflectionpb "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"

	common "github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

/* -------------------------------------------------------------------------- */
/*  Exported fingerprinter                                                    */
/* -------------------------------------------------------------------------- */

type Fingerprinter struct{}

func (Fingerprinter) Name() string { return "grpc" }

func (Fingerprinter) Detect(ctx context.Context, ip net.IP, cfg discoverfern.DiscoverServiceConfig) (*discoverfern.ServiceDetails, error) {
	addr := fmt.Sprintf("%s:%d", ip, cfg.Port)
	timeout := time.Duration(cfg.Timeout) * time.Second

	/* ---- try plaintext first --------------------------------------------- */
	conn, tlsUsed, err := dial(ctx, addr, timeout, false)
	if err != nil {
		/* ---- fallback to opportunistic TLS -------------------------------- */
		conn, tlsUsed, err = dial(ctx, addr, timeout, true)
		if err != nil {
			return nil, nil // neither path worked → not gRPC
		}
	}
	defer conn.Close()

	/* ---- Server-reflection ListServices ---------------------------------- */
	rctx, cancel := context.WithTimeout(ctx, timeout/2)
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
		return buildResult(cfg, ip, tlsUsed, "LIST_OK"), nil

	//   2. gRPC status UNIMPLEMENTED → still gRPC (reflection disabled)
	case err != nil && status.Code(err) == codes.Unimplemented:
		return buildResult(cfg, ip, tlsUsed, "UNIMPLEMENTED"), nil

	//   otherwise → not gRPC
	default:
		return nil, nil
	}
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

func dial(ctx context.Context, addr string, to time.Duration, useTLS bool) (*grpc.ClientConn, bool, error) {
	dctx, cancel := context.WithTimeout(ctx, to)
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

func buildResult(cfg discoverfern.DiscoverServiceConfig, ip net.IP, tlsUsed bool, statusStr string) *discoverfern.ServiceDetails {
	transport := "TCP"
	if tlsUsed {
		transport = "TCPTLS"
	}
	meta := map[string]string{"reflection": statusStr}

	return &discoverfern.ServiceDetails{
		Host:      cfg.Target,
		Ip:        ip.String(),
		Port:      cfg.Port,
		Tls:       tlsUsed,
		Version:   nil,
		Transport: enumTransport(transport),
		Protocol:  enumProtocol("GRPC"),
		Metadata:  meta,
	}
}

func enumTransport(s string) common.TransportType {
	e, err := common.NewTransportTypeFromString(s)
	if err != nil {
		e, _ = common.NewTransportTypeFromString("UNKNOWN")
	}
	return e
}

func enumProtocol(s string) common.ProtocolType {
	e, err := common.NewProtocolTypeFromString(s)
	if err != nil {
		e, _ = common.NewProtocolTypeFromString("UNKNOWN")
	}
	return e
}
