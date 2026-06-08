// Package mongodb provides MongoDB service enumeration functionality.
package mongodb

import (
	"context"
	"fmt"
	"time"

	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	mongodbfern "github.com/Method-Security/networkscan/generated/go/enumerate/mongodb"
	"github.com/Method-Security/networkscan/utils"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const defaultPort = 27017
const defaultTimeoutMs = 10000

// LibraryEnumerateMongoDB implements NetworkApplicationLibrary for MongoDB enumeration.
// It probes MongoDB targets for anonymous access and enumerates databases/collections.
type LibraryEnumerateMongoDB struct{}

// EnumerateTarget connects to a MongoDB instance (anonymously), probes server info,
// detects unauthenticated access, and — if accessible — enumerates databases and collections.
func (m *LibraryEnumerateMongoDB) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting MongoDB enumeration", svc1log.SafeParam("target", target))

	details := mongodbfern.EnumerateMongodbDetails{Target: target}
	var errors []string

	host, port := utils.ParseHostPort(target, defaultPort)
	if host == "" {
		errors = append(errors, fmt.Sprintf("invalid target %q: could not parse host:port", target))
		return &enumeratefern.EnumerateServiceDetails{EnumerateMongodbDetails: &details}, errors
	}

	addr := utils.FormatHostPort(host, port)
	details.Target = addr

	// Connect anonymously (no credentials). Derive timeout from context deadline if set.
	timeoutMs := defaultTimeoutMs
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			timeoutMs = int(remaining.Milliseconds())
		}
	}
	client, err := connectAnonymous(ctx, host, port, timeoutMs)
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to connect: %v", err))
		return &enumeratefern.EnumerateServiceDetails{EnumerateMongodbDetails: &details}, errors
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	// Ping to verify connectivity
	if pingErr := client.Ping(ctx, nil); pingErr != nil {
		errors = append(errors, fmt.Sprintf("ping failed: %v", pingErr))
		return &enumeratefern.EnumerateServiceDetails{EnumerateMongodbDetails: &details}, errors
	}

	// Collect server information
	serverInfo := gatherServerInfo(ctx, client)
	details.ServerInfo = serverInfo

	// Check for anonymous (unauthenticated) database access
	dbNames, listErr := client.ListDatabaseNames(ctx, map[string]interface{}{})
	if listErr != nil {
		errors = append(errors, fmt.Sprintf("list databases failed: %v", listErr))
		anonAllowed := false
		details.AnonymousAccessAllowed = &anonAllowed
		log.Info("Anonymous MongoDB access denied", svc1log.SafeParam("target", addr))
		return &enumeratefern.EnumerateServiceDetails{EnumerateMongodbDetails: &details}, errors
	}

	anonAllowed := true
	details.AnonymousAccessAllowed = &anonAllowed
	log.Info("Anonymous MongoDB access allowed — enumerating",
		svc1log.SafeParam("target", addr),
		svc1log.SafeParam("databases", len(dbNames)))

	// Enumerate databases and collections
	var dbInfos []*mongodbfern.DatabaseInfo
	for _, dbName := range dbNames {
		dbInfo := &mongodbfern.DatabaseInfo{Name: dbName}
		db := client.Database(dbName)

		collNames, colErr := db.ListCollectionNames(ctx, map[string]interface{}{})
		if colErr != nil {
			log.Debug("Could not list collections",
				svc1log.SafeParam("database", dbName),
				svc1log.SafeParam("error", colErr))
		} else {
			for _, collName := range collNames {
				collInfo := &mongodbfern.CollectionInfo{Name: collName}
				count, countErr := db.Collection(collName).EstimatedDocumentCount(ctx)
				if countErr == nil {
					collInfo.DocumentCount = &count
				}
				dbInfo.Collections = append(dbInfo.Collections, collInfo)
			}
		}
		dbInfos = append(dbInfos, dbInfo)
	}
	details.Databases = dbInfos

	return &enumeratefern.EnumerateServiceDetails{EnumerateMongodbDetails: &details}, errors
}

// connectAnonymous creates an unauthenticated MongoDB client with the given timeout.
func connectAnonymous(ctx context.Context, host string, port, timeoutMs int) (*mongo.Client, error) {
	uri := fmt.Sprintf("mongodb://%s", utils.FormatHostPort(host, port))
	dur := time.Duration(timeoutMs) * time.Millisecond

	opts := options.Client().
		ApplyURI(uri).
		SetServerSelectionTimeout(dur).
		SetConnectTimeout(dur).
		SetSocketTimeout(dur).
		SetDirect(true)

	return mongo.Connect(ctx, opts)
}

// gatherServerInfo attempts to collect MongoDB build information via an admin command.
func gatherServerInfo(ctx context.Context, client *mongo.Client) *commonprotocolfern.MongodbServerInfo {
	info := &commonprotocolfern.MongodbServerInfo{}

	var buildResult map[string]interface{}
	if err := client.Database("admin").RunCommand(ctx, map[string]interface{}{"buildInfo": 1}).Decode(&buildResult); err != nil {
		return info
	}

	if v, ok := buildResult["version"].(string); ok {
		info.Version = &v
	}
	if git, ok := buildResult["gitVersion"].(string); ok {
		info.BuildInfo = &git
	}
	if se, ok := buildResult["storageEngines"].([]interface{}); ok && len(se) > 0 {
		if seStr, ok := se[0].(string); ok {
			info.StorageEngine = &seStr
		}
	}
	if maxBson, ok := buildResult["maxBsonObjectSize"].(int32); ok {
		mb := int(maxBson)
		info.MaxBsonObjectSize = &mb
	}
	if maxMsg, ok := buildResult["maxMessageSizeBytes"].(int32); ok {
		mm := int(maxMsg)
		info.MaxMessageSizeBytes = &mm
	}

	return info
}
