package wireio

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
)

func TestGRPCConnectionSurvivesDialAndCarriesRawProtobuf(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	response := []byte{0x12, 5, '2', '.', '6', '.', '7'}
	server := grpc.NewServer(grpc.ForceServerCodec(rawCodec{}), grpc.UnknownServiceHandler(func(_ interface{}, stream grpc.ServerStream) error {
		var request []byte
		if err := stream.RecvMsg(&request); err != nil {
			return err
		}
		return stream.SendMsg(response)
	}))
	defer server.Stop()
	go func() { _ = server.Serve(l) }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := GRPCDialWithTimeout(ctx, l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	got, err := GRPCInvokeUnary(ctx, conn, "/milvus.proto.milvus.MilvusService/GetVersion", []byte{}, time.Second)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("response=%x error=%v", got, err)
	}
	cancel()
	if _, err := GRPCInvokeUnary(ctx, conn, "/milvus.proto.milvus.MilvusService/GetVersion", []byte{}, time.Second); err == nil {
		t.Fatal("cancelled call succeeded")
	}
}
