// Package plugins provides MongoDB service fingerprinting using the official MongoDB driver
package plugins

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	"github.com/Method-Security/networkscan/utils"
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
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()

	// Create MongoDB connection string
	addr := utils.FormatHostPort(ip.String(), port)
	uri := fmt.Sprintf("mongodb://%s", addr)

	// Create context with timeout
	timeoutDuration := boundedMongoProbeTimeout(timeout)
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, ctx.Err()
		}
		// Leave half the attempt budget for the native HTTP warning fallback.
		timeoutDuration = min(timeoutDuration, remaining/2)
	}
	timeoutCtx, cancelDriver := helpers.ContextDuration(ctx, timeoutDuration)
	defer cancelDriver()

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
		if result, warnErr := detectMongoDBNativeHTTPWarning(ctx, ip, port, host, timeout); warnErr == nil {
			return result, nil
		}
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

	return buildMongoDBResult(host, ip, port, false, version, buildInfo, unauthenticatedAccess, storageEngine, maxBsonObjectSize, maxMessageSizeBytes), nil
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

func buildMongoDBResult(host string, ip net.IP, port int, tlsEnabled bool, version string, buildInfo string, unauthenticatedAccess bool, storageEngine *string, maxBsonObjectSize *int, maxMessageSizeBytes *int) *discoverfern.ServiceDetails {
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
		Tls:       helpers.BoolPtr(tlsEnabled),
		Version:   &version,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeMongodb,
		Metadata:  &discoverfern.ServiceMetadata{Mongodb: metadata},
	}
}

func detectMongoDBNativeHTTPWarning(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	for index, tlsEnabled := range []bool{true, false} {
		attemptTimeout := boundedMongoWarningTimeout(timeout)
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return nil, ctx.Err()
			}
			// A stalled TLS probe must leave time for the plaintext attempt.
			attemptTimeout = min(attemptTimeout, remaining/time.Duration(2-index))
		}
		attemptCtx, cancel := helpers.ContextDuration(ctx, attemptTimeout)
		resp, err := mongoHTTPWarningExchange(attemptCtx, ip, port, host, timeout, tlsEnabled)
		cancel()
		if err != nil {
			continue
		}
		if version, ok := mongoVersionFromNativeHTTPWarning(resp); ok {
			return buildMongoDBResult(host, ip, port, tlsEnabled, version, "", false, nil, nil, nil), nil
		}
	}
	return nil, fmt.Errorf("no MongoDB native HTTP warning")
}

func mongoHTTPWarningExchange(ctx context.Context, ip net.IP, port int, host string, timeout int, tlsEnabled bool) ([]byte, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	exchangeTimeout := boundedMongoWarningTimeout(timeout)
	conn, err := helpers.DialDuration(ctx, "tcp", addr, exchangeTimeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if tlsEnabled {
		tlsConn := tls.Client(conn, helpers.DiscoveryTLSConfig(host))
		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}
		conn = tlsConn
	}

	request := "GET / HTTP/1.0\r\n"
	if host != "" && net.ParseIP(host) == nil {
		request += "Host: " + net.JoinHostPort(host, fmt.Sprintf("%d", port)) + "\r\n"
	}
	if userAgent := helpers.HTTPUserAgent(ctx); userAgent != "" {
		request += "User-Agent: " + userAgent + "\r\n"
	}
	if _, err := conn.Write([]byte(request + "\r\n")); err != nil {
		return nil, err
	}
	buf := make([]byte, 512)
	var resp []byte
	for len(resp) < 2048 {
		n, err := conn.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
			if bytes.Contains(resp, []byte("It looks like you are trying to access MongoDB over HTTP on the native driver port.\r\n")) ||
				bytes.Contains(resp, []byte("You are trying to access MongoDB on the native driver port. For http diagnostic access, add 1000 to the port number")) {
				return resp, nil
			}
		}
		if err != nil {
			if len(resp) > 0 {
				return resp, nil
			}
			return nil, err
		}
	}
	return resp, nil
}

func boundedMongoProbeTimeout(timeout int) time.Duration {
	fallback := 3 * time.Second
	if !helpers.HasTimeout(timeout) {
		return fallback
	}
	configured := helpers.Timeout(timeout)
	if configured <= 0 {
		return fallback
	}
	return configured
}

func boundedMongoWarningTimeout(timeout int) time.Duration {
	limit := 2 * time.Second
	if !helpers.HasTimeout(timeout) {
		return limit
	}
	configured := helpers.Timeout(timeout)
	if configured <= 0 || configured > limit {
		return limit
	}
	return configured
}

func mongoVersionFromNativeHTTPWarning(resp []byte) (string, bool) {
	switch {
	case bytes.Contains(resp, []byte("It looks like you are trying to access MongoDB over HTTP on the native driver port.\r\n")):
		return "MongoDB 3.6 after 3.6.3, or 3.7.3 or later", true
	case bytes.Contains(resp, []byte("It looks like you are trying to access MongoDB over HTTP on the native driver port.")):
		return "MongoDB 2.5.1 - 3.5.13", true
	case bytes.Contains(resp, []byte("You are trying to access MongoDB on the native driver port. For http diagnostic access, add 1000 to the port number")):
		return "MongoDB 2.5.0 or earlier", true
	default:
		return "", false
	}
}
