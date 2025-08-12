package smb

import (
	"context"

	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// MapProtocolVersionToEnum maps protocol version strings to Fern enum values
// This function is shared between enumerate and pentest modules
func MapProtocolVersionToEnum(version string) (commonprotocolfern.SmbVersion, bool) {
	switch version {
	case "SMB3.0.2":
		return commonprotocolfern.SmbVersionSmb302, true
	case "SMB3.0":
		return commonprotocolfern.SmbVersionSmb30, true
	case "SMB2.1":
		return commonprotocolfern.SmbVersionSmb21, true
	case "SMB2.0":
		return commonprotocolfern.SmbVersionSmb20, true
	default:
		return "", false // Unknown version
	}
}

// ConnectionResult holds the result of a connection test
type ConnectionResult struct {
	Client     *Client
	ServerInfo *commonprotocolfern.SmbServerInfo
	Success    bool
	Error      error
}

// TestConnectionMethod tests a specific SMB connection method and extracts server info
// This helper reduces duplication in connection testing patterns
func TestConnectionMethod(ctx context.Context, host string, port int, setupFunc func(*Client), methodName, target string) *ConnectionResult {
	log := svc1log.FromContext(ctx)

	client := NewClient(host, port)
	setupFunc(client)

	err := client.ConnectWithContext(ctx)
	result := &ConnectionResult{
		Client:  client,
		Success: err == nil,
		Error:   err,
	}

	// Always try to extract server info (works even on failed connections via NTLM challenge)
	if serverInfo := client.GetServerInfo(); serverInfo != nil {
		result.ServerInfo = serverInfo
	}

	if err == nil {
		log.Info(methodName+" allowed", svc1log.SafeParam("target", target))
	} else {
		log.Debug(methodName+" failed", svc1log.SafeParam("error", err.Error()))
	}

	return result
}
