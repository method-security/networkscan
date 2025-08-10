package common

import (
	"context"
	"time"

	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	smbclient "github.com/Method-Security/networkscan/internal/protocol/smb"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// NTLMServerInfoExtractor provides shared functionality for extracting NTLM server information
// via SMB connection. This is used by multiple modules (LDAP, SMB, etc.) that need to extract
// Windows server information from NTLM challenges.
type NTLMServerInfoExtractor struct{}

// NewNTLMServerInfoExtractor creates a new NTLM server info extractor
func NewNTLMServerInfoExtractor() *NTLMServerInfoExtractor {
	return &NTLMServerInfoExtractor{}
}

// ExtractServerInfo attempts to extract NTLM server info by connecting to SMB port 445
// This works for any service running on a Windows server that supports NTLM authentication
func (e *NTLMServerInfoExtractor) ExtractServerInfo(ctx context.Context, host string, target string) *commonprotocolfern.SmbServerInfo {
	log := svc1log.FromContext(ctx)
	log.Debug("Attempting to extract NTLM server info via SMB",
		svc1log.SafeParam("host", host),
		svc1log.SafeParam("target", target))

	// Create SMB client to extract server info from NTLM challenge
	client := smbclient.NewClient(host, 445)
	client.Timeout = 10 * time.Second

	serverInfo, err := client.ExtractServerInfoFromChallenge(ctx)
	if err != nil {
		log.Debug("Failed to extract NTLM server info via SMB", svc1log.SafeParam("error", err.Error()))
		return nil
	}

	log.Debug("Successfully extracted NTLM server info via SMB",
		svc1log.SafeParam("serverName", serverInfo.ServerName),
		svc1log.SafeParam("domain", serverInfo.Domain),
		svc1log.SafeParam("osVersion", serverInfo.OSVersion))

	return convertSmbServerInfoToFern(serverInfo)
}

// convertSmbServerInfoToFern converts internal SMB ServerInfo to fern SmbServerInfo
func convertSmbServerInfoToFern(serverInfo *smbclient.ServerInfo) *commonprotocolfern.SmbServerInfo {
	if serverInfo == nil {
		return nil
	}

	// Convert capabilities
	var capabilities []string
	if serverInfo.Capabilities != nil {
		capabilities = serverInfo.Capabilities
	}

	// Convert supported versions
	var supportedVersions []commonprotocolfern.SmbVersion
	for _, version := range serverInfo.SupportedVersions {
		if smbVersion, err := commonprotocolfern.NewSmbVersionFromString(version); err == nil {
			supportedVersions = append(supportedVersions, smbVersion)
		}
	}

	return &commonprotocolfern.SmbServerInfo{
		ServerName:           &serverInfo.ServerName,
		Domain:               &serverInfo.Domain,
		NetBiosDomainName:    &serverInfo.NetBIOSDomainName,
		OsVersion:            &serverInfo.OSVersion,
		RawOsVersion:         &serverInfo.RawOSVersion,
		SigningRequired:      &serverInfo.SigningRequired,
		SupportedSmbVersions: supportedVersions,
		Capabilities:         capabilities,
	}
}
