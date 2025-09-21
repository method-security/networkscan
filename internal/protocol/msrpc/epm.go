package msrpc

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dcetypes"
	drsuapi "github.com/oiweiwei/go-msrpc/msrpc/drsr/drsuapi/v4"
	epm "github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/well_known"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// EndpointMapper provides functionality for discovering RPC endpoints via EPM
type EndpointMapper struct {
	Host        string
	AuthOptions []dcerpc.Option
}

// NewEndpointMapper creates a new endpoint mapper client with dcerpc auth options
func NewEndpointMapper(host string, authOptions []dcerpc.Option) *EndpointMapper {
	return &EndpointMapper{
		Host:        host,
		AuthOptions: authOptions,
	}
}

// DiscoverDRSUAPIEndpoints queries EPM for DRSUAPI TCP endpoints using the library
func (m *EndpointMapper) DiscoverDRSUAPIEndpoints(ctx context.Context) ([]dcerpc.StringBinding, error) {
	log := svc1log.FromContext(ctx)
	log.Debug("EndpointMapper: querying EPM for DRSUAPI endpoints", svc1log.SafeParam("host", m.Host))

	var epmConn dcerpc.Conn
	var epmClient epm.EpmClient
	var err error

	if len(m.AuthOptions) > 0 {
		// Use provided dcerpc auth options (like SAMR and DRSUAPI clients)
		log.Debug("EndpointMapper: using dcerpc auth options")
		// Combine endpoint mapper binding with auth options
		opts := append([]dcerpc.Option{well_known.EndpointMapper()}, m.AuthOptions...)
		epmConn, err = dcerpc.Dial(ctx, m.Host, opts...)
		if err != nil {
			log.Error("Failed to connect to EPM service with auth", svc1log.SafeParam("error", err.Error()))
			return nil, fmt.Errorf("failed to connect to EPM service: %w", err)
		}
		defer func() {
			if closeErr := epmConn.Close(ctx); closeErr != nil {
				log.Warn("Failed to close EPM connection", svc1log.SafeParam("error", closeErr.Error()))
			}
		}()

		// Create EPM client
		epmClient, err = epm.NewEpmClient(ctx, epmConn)
	} else {
		// Connect anonymously to EPM service (no authentication like impacket)
		log.Debug("EndpointMapper: connecting anonymously to EPM service")
		epmConn, err = dcerpc.Dial(ctx, m.Host, well_known.EndpointMapper())
		if err != nil {
			log.Error("Failed to connect to EPM service", svc1log.SafeParam("error", err.Error()))
			return nil, fmt.Errorf("failed to connect to EPM service: %w", err)
		}
		defer func() {
			if closeErr := epmConn.Close(ctx); closeErr != nil {
				log.Warn("Failed to close EPM connection", svc1log.SafeParam("error", closeErr.Error()))
			}
		}()

		// Create anonymous EPM client (with insecure flag for no authentication)
		epmClient, err = epm.NewEpmClient(ctx, epmConn, dcerpc.WithInsecure())
	}
	if err != nil {
		log.Error("Failed to create EPM client", svc1log.SafeParam("error", err.Error()))
		return nil, fmt.Errorf("failed to create EPM client: %w", err)
	}

	// Build EPM tower for DRSUAPI lookup using library functions (following example pattern)
	tower := buildDRSUAPITower()

	// Query EPM using library's ept_map operation
	mapResp, err := epmClient.Map(ctx, &epm.MapRequest{
		MapTower:    tower,
		EntryHandle: &epm.LookupHandle{}, // Empty entry handle
		MaxTowers:   4,                   // Request up to 4 towers
	})
	if err != nil {
		log.Error("EPM Map request failed", svc1log.SafeParam("error", err.Error()))
		return nil, fmt.Errorf("EPM map request failed: %w", err)
	}

	if mapResp.TowersLength == 0 {
		log.Warn("EPM returned no towers for DRSUAPI")
		return nil, fmt.Errorf("no DRSUAPI endpoints found via EPM")
	}

	log.Info("EPM returned towers", svc1log.SafeParam("towerCount", mapResp.TowersLength))

	// Extract bindings from towers using library's Tower.Binding() method
	var result []dcerpc.StringBinding
	for i, tower := range mapResp.Towers {
		if tower == nil {
			continue
		}

		binding := tower.Binding()
		if binding == nil {
			log.Debug("Tower has no binding", svc1log.SafeParam("towerIndex", i))
			continue
		}

		// Filter for TCP bindings
		if binding.StringBinding.ProtocolSequence == dcerpc.ProtocolSequenceIPTCP {
			// Override network address with our target host
			binding.StringBinding.NetworkAddress = m.Host
			result = append(result, binding.StringBinding)
			log.Info("Found DRSUAPI TCP endpoint",
				svc1log.SafeParam("endpoint", binding.StringBinding.Endpoint),
				svc1log.SafeParam("protocol", binding.StringBinding.ProtocolSequence))
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no TCP endpoints found for DRSUAPI")
	}

	return result, nil
}

// buildDRSUAPITower creates EPM tower for DRSUAPI lookup using library functions (following example pattern)
func buildDRSUAPITower() *dcetypes.Tower {
	// Build tower following the example pattern in epm.go
	drsuapiSyntax := drsuapi.DrsuapiSyntaxV4_0
	return dcetypes.FloorsToTower([]*dcetypes.Floor{
		// Floor 1: DRSUAPI Interface UUID
		{
			Protocol:     uint8(dcetypes.ProtocolUUID),
			UUID:         drsuapiSyntax.IfUUID,
			VersionMajor: drsuapiSyntax.IfVersionMajor,
			Data:         []byte{0, 0}, // Minor version
		},
		// Floor 2: NDR Data Representation (using library constant)
		{
			Protocol:     uint8(dcetypes.ProtocolUUID),
			UUID:         dcerpc.TransferNDR,
			VersionMajor: 2, // NDR v2
			Data:         binary.LittleEndian.AppendUint16(nil, drsuapiSyntax.IfVersionMinor),
		},
		// Floor 3: RPC Protocol
		{
			Protocol: uint8(dcetypes.ProtocolRPC_CO), // RPC connection-oriented
			Data:     []byte{0, 0},                   // Default RPC version
		},
		// Floor 4: TCP Protocol (port 0 = dynamic)
		{
			Protocol: uint8(dcetypes.ProtocolTCP), // TCP
			Data:     []byte{0, 0},                // Port 0 (dynamic allocation)
		},
		// Floor 5: IP Address (0.0.0.0 = any)
		{
			Protocol: uint8(dcetypes.ProtocolIP), // IP
			Data:     []byte{0, 0, 0, 0},         // IP 0.0.0.0 (any address)
		},
	})
}
