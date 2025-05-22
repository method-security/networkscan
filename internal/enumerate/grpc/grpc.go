package grpc

import (
	// Standard
	"context"
	"encoding/base64"
	"fmt"
	"time"

	// Generated
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	grpc "github.com/Method-Security/networkscan/generated/go/enumerate/grpc"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	grpcLib "google.golang.org/grpc"
	insecure "google.golang.org/grpc/credentials/insecure"
	grpc_reflection_v1alpha "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	proto "google.golang.org/protobuf/proto"
	descriptorpb "google.golang.org/protobuf/types/descriptorpb"
)

// LibraryEnumerateGRPC implements NetworkApplicationLibrary for GRPC enumeration.
type LibraryEnumerateGRPC struct{}

// EnumerateTarget performs a gRPC scan against a target URL and returns the report.
func (lib *LibraryEnumerateGRPC) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	var details grpc.EnumerateGrpcDetails
	details.Target = target
	errors := []string{}
	log := svc1log.FromContext(ctx)
	log.Info("Enumerating target", svc1log.SafeParam("target", target))

	conn, err := connectToGRPCServer(ctx, target)
	if err != nil {
		errors = append(errors, err.Error())
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateGrpcDetails(&details), errors
	}
	defer closeConnection(conn)

	stream, err := createReflectionClient(ctx, conn)
	if err != nil {
		errors = append(errors, err.Error())
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateGrpcDetails(&details), errors
	}

	services, err := requestAndReceiveServices(stream)
	if err != nil {
		errors = append(errors, err.Error())
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateGrpcDetails(&details), errors
	}

	rawDescriptors, err := processServices(stream, services, &details)
	if err != nil {
		errors = append(errors, err.Error())
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateGrpcDetails(&details), errors
	}

	if err := encodeRawDescriptors(rawDescriptors, &details); err != nil {
		errors = append(errors, err.Error())
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateGrpcDetails(&details), errors
	}

	return enumeratefern.NewEnumerateServiceDetailsFromEnumerateGrpcDetails(&details), errors
}

// connectToGRPCServer dials the target with a timeout.
func connectToGRPCServer(ctx context.Context, target string) (*grpcLib.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	return grpcLib.DialContext(
		ctx,
		target,
		grpcLib.WithTransportCredentials(insecure.NewCredentials()),
		grpcLib.WithBlock(),
	)
}

// closeConnection closes the gRPC connection.
func closeConnection(conn *grpcLib.ClientConn) {
	_ = conn.Close()
}

// createReflectionClient opens a reflection stream.
func createReflectionClient(ctx context.Context, conn *grpcLib.ClientConn) (grpc_reflection_v1alpha.ServerReflection_ServerReflectionInfoClient, error) {
	client := grpc_reflection_v1alpha.NewServerReflectionClient(conn)
	return client.ServerReflectionInfo(ctx)
}

// requestAndReceiveServices lists services via reflection.
func requestAndReceiveServices(stream grpc_reflection_v1alpha.ServerReflection_ServerReflectionInfoClient) ([]*grpc_reflection_v1alpha.ServiceResponse, error) {
	if err := stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_ListServices{
			ListServices: "*",
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to request list of services: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive list of services: %v", err)
	}

	return resp.GetListServicesResponse().Service, nil
}

// processServices gathers descriptors and extracts method info.
func processServices(stream grpc_reflection_v1alpha.ServerReflection_ServerReflectionInfoClient, services []*grpc_reflection_v1alpha.ServiceResponse, details *grpc.EnumerateGrpcDetails) ([]*descriptorpb.FileDescriptorProto, error) {
	var rawDescriptors []*descriptorpb.FileDescriptorProto

	for _, service := range services {
		serviceName := service.Name

		if err := requestFileDescriptor(stream, serviceName); err != nil {
			return nil, fmt.Errorf("failed to request file descriptor for service %s: %v", serviceName, err)
		}

		fileDescriptorBytes, err := receiveFileDescriptor(stream, serviceName)
		if err != nil {
			return nil, fmt.Errorf("failed to receive file descriptor for service %s: %v", serviceName, err)
		}

		if err := unmarshalFileDescriptors(fileDescriptorBytes, &rawDescriptors, details); err != nil {
			return nil, fmt.Errorf("failed to unmarshal file descriptor: %v", err)
		}
	}

	return rawDescriptors, nil
}

// requestFileDescriptor requests a file descriptor for a symbol.
func requestFileDescriptor(stream grpc_reflection_v1alpha.ServerReflection_ServerReflectionInfoClient, serviceName string) error {
	return stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_FileContainingSymbol{
			FileContainingSymbol: serviceName,
		},
	})
}

// receiveFileDescriptor receives a file descriptor response.
func receiveFileDescriptor(stream grpc_reflection_v1alpha.ServerReflection_ServerReflectionInfoClient, serviceName string) ([][]byte, error) {
	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive file descriptor for service %s: %v", serviceName, err)
	}
	return resp.GetFileDescriptorResponse().FileDescriptorProto, nil
}

// unmarshalFileDescriptors decodes descriptors and populates method details.
func unmarshalFileDescriptors(fileDescriptorBytes [][]byte, rawDescriptors *[]*descriptorpb.FileDescriptorProto, details *grpc.EnumerateGrpcDetails) error {
	for _, fdBytes := range fileDescriptorBytes {
		var fileDesc descriptorpb.FileDescriptorProto
		if err := proto.Unmarshal(fdBytes, &fileDesc); err != nil {
			return fmt.Errorf("failed to unmarshal file descriptor: %v", err)
		}
		*rawDescriptors = append(*rawDescriptors, &fileDesc)

		extractMethods(&fileDesc, details)
	}
	return nil
}

// extractMethods converts proto methods into Fern RpcMethod & GrpcService.
func extractMethods(fileDesc *descriptorpb.FileDescriptorProto, details *grpc.EnumerateGrpcDetails) {
	for _, service := range fileDesc.Service {
		var svc grpc.GrpcService
		svc.Name = service.GetName()

		for _, method := range service.Method {
			requestFields := extractFields(fileDesc, method.GetInputType())

			rpc := grpc.RpcMethod{
				Name:            method.GetName(),
				FullPath:        fmt.Sprintf("/%s/%s", service.GetName(), method.GetName()),
				RequestType:     method.GetInputType(),
				ResponseType:    method.GetOutputType(),
				ClientStreaming: method.GetClientStreaming(),
				ServerStreaming: method.GetServerStreaming(),
				RequestFields:   requestFields,
			}
			svc.Methods = append(svc.Methods, &rpc)
		}
		details.Services = append(details.Services, &svc)
	}
}

// encodeRawDescriptors stores the base-64 descriptor set.
func encodeRawDescriptors(rawDescriptors []*descriptorpb.FileDescriptorProto, details *grpc.EnumerateGrpcDetails) error {
	rawData, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: rawDescriptors})
	if err != nil {
		return fmt.Errorf("failed to marshal raw descriptors: %v", err)
	}
	details.RawDescriptorSet = base64.StdEncoding.EncodeToString(rawData)
	return nil
}

// extractFields returns the field names for a message type.
func extractFields(fileDesc *descriptorpb.FileDescriptorProto, messageType string) []string {
	var fields []string
	for _, msg := range fileDesc.MessageType {
		if fmt.Sprintf(".%s.%s", fileDesc.GetPackage(), msg.GetName()) == messageType {
			for _, field := range msg.Field {
				fields = append(fields, field.GetName())
			}
			break
		}
	}
	return fields
}
