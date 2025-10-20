// Package plugins provides MongoDB service fingerprinting using the official MongoDB driver
package plugins

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

/* -------------------------------------------------------------------------- */
/*  Exported fingerprinter                                                    */
/* -------------------------------------------------------------------------- */

type MongoDBFingerprinter struct{}

func (MongoDBFingerprinter) Name() string { return "mongodb" }

func (MongoDBFingerprinter) DefaultPorts() []int { return []int{27017} }

func (MongoDBFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Create MongoDB connection string
	addr := fmt.Sprintf("%s:%d", ip, port)
	uri := fmt.Sprintf("mongodb://%s", addr)

	// Create context with timeout
	timeoutDuration := time.Duration(timeout) * time.Second
	timeoutCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	// Set client options with short timeout
	clientOptions := options.Client().
		ApplyURI(uri).
		SetServerSelectionTimeout(timeoutDuration).
		SetConnectTimeout(timeoutDuration).
		SetSocketTimeout(timeoutDuration).
		SetDirect(true) // Direct connection, bypass server discovery

	// Connect to MongoDB
	client, err := mongo.Connect(timeoutCtx, clientOptions)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	// Ping to verify connection and get server info
	if err := client.Ping(timeoutCtx, nil); err != nil {
		return nil, nil
	}

	version := ""
	buildInfo := ""
	unauthenticatedAccess := false
	var storageEngine *string
	var maxBsonObjectSize *int
	var maxMessageSizeBytes *int

	// Try to get build info (requires no authentication by default)
	var result map[string]interface{}
	err = client.Database("admin").RunCommand(timeoutCtx, map[string]interface{}{"buildInfo": 1}).Decode(&result)
	if err == nil {
		if v, ok := result["version"].(string); ok {
			version = v
		}
		if gitVersion, ok := result["gitVersion"].(string); ok {
			buildInfo = gitVersion
		}
		if se, ok := result["storageEngines"].([]interface{}); ok && len(se) > 0 {
			if seStr, ok := se[0].(string); ok {
				storageEngine = &seStr
			}
		}
		if maxBson, ok := result["maxBsonObjectSize"].(int32); ok {
			maxBsonInt := int(maxBson)
			maxBsonObjectSize = &maxBsonInt
		}
		if maxMsg, ok := result["maxMessageSizeBytes"].(int32); ok {
			maxMsgInt := int(maxMsg)
			maxMessageSizeBytes = &maxMsgInt
		}
	}

	// Try to list databases - this requires authentication if auth is enabled
	// If this succeeds without credentials, authentication is NOT required
	dbNames, err := client.ListDatabaseNames(timeoutCtx, map[string]interface{}{})
	if err == nil && len(dbNames) > 0 {
		unauthenticatedAccess = true
	}

	// If we couldn't get version from buildInfo, at least we know it's MongoDB
	if version == "" {
		version = "MongoDB (version unknown)"
	}

	return buildMongoDBResult(host, ip, port, version, buildInfo, unauthenticatedAccess, storageEngine, maxBsonObjectSize, maxMessageSizeBytes), nil
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

func buildMongoDBResult(host string, ip net.IP, port int, version string, buildInfo string, unauthenticatedAccess bool, storageEngine *string, maxBsonObjectSize *int, maxMessageSizeBytes *int) *discoverfern.ServiceDetails {
	var buildInfoPtr *string
	if buildInfo != "" {
		buildInfoPtr = &buildInfo
	}

	metadata := &protocol.MongodbServerInfo{
		Version:               &version,
		BuildInfo:             buildInfoPtr,
		UnauthenticatedAccess: &unauthenticatedAccess,
		StorageEngine:         storageEngine,
		MaxBsonObjectSize:     maxBsonObjectSize,
		MaxMessageSizeBytes:   maxMessageSizeBytes,
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Version:   &version,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeMongodb,
		Metadata:  discoverfern.NewServiceMetadataFromMongodb(metadata),
	}
}
