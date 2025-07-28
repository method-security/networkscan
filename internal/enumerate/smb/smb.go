package smb

import (
	"context"
	"fmt"
	"time"

	smbfern "github.com/Method-Security/networkscan/generated/go/common/smb"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	smb "github.com/Method-Security/networkscan/generated/go/enumerate/smb"
	smbclient "github.com/Method-Security/networkscan/internal/protocol/smb"
	"github.com/Method-Security/networkscan/utils"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumerateSMB implements NetworkApplicationLibrary for SMB enumeration using the shared protocol library.
type LibraryEnumerateSMB struct{}

// EnumerateTarget performs comprehensive SMB enumeration using the shared SMB protocol library
func (s *LibraryEnumerateSMB) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	var details smb.EnumerateSmbDetails
	details.Target = target
	errors := []string{}

	log := svc1log.FromContext(ctx)
	log.Info("Starting SMB enumeration for target", svc1log.SafeParam("target", target))

	host, port := utils.ParseHostPort(target, 445)

	// Create SMB client using shared protocol library
	client := smbclient.NewClient(host, port)

	// Test all connection methods and extract server info
	var serverInfo *smbclient.ServerInfo
	var authAttempts []*smbfern.AuthAttempt
	var nullSessionAllowed, anonymousAllowed, guestAllowed bool
	var connectionSuccessful bool
	var workingClient *smbclient.Client

	// Test null session first
	nullResult := smbclient.TestConnectionMethod(ctx, host, port,
		func(c *smbclient.Client) { c.SetNullSession() },
		"Null session", target)

	if nullResult.Success {
		nullSessionAllowed = true
		connectionSuccessful = true
		workingClient = nullResult.Client
		if nullResult.ServerInfo != nil {
			serverInfo = nullResult.ServerInfo
		}
	} else {
		// Extract server info even if connection failed (from NTLM challenge)
		if serverInfo == nil && nullResult.ServerInfo != nil {
			serverInfo = nullResult.ServerInfo
		}
		_ = nullResult.Client.Close()
	}

	// Test anonymous connection if null session failed
	if !connectionSuccessful {
		anonResult := smbclient.TestConnectionMethod(ctx, host, port,
			func(c *smbclient.Client) { c.SetAnonymous() },
			"Anonymous login", target)

		if anonResult.Success {
			anonymousAllowed = true
			connectionSuccessful = true
			workingClient = anonResult.Client
			if anonResult.ServerInfo != nil {
				serverInfo = anonResult.ServerInfo
			}
		} else {
			// Extract server info even if connection failed (from NTLM challenge)
			if serverInfo == nil && anonResult.ServerInfo != nil {
				serverInfo = anonResult.ServerInfo
			}
			_ = anonResult.Client.Close()
		}
	}

	// Test guest authentication (this is a real credential-based auth attempt)
	// We test this separately to record the auth attempt
	guestResult := smbclient.TestConnectionMethod(ctx, host, port,
		func(c *smbclient.Client) { c.SetCredentials("guest", "", "") },
		"Guest authentication", target)

	guestAttempt := &smbfern.AuthAttempt{
		Username:  "guest",
		Password:  "",
		Success:   guestResult.Success,
		Timestamp: time.Now(),
	}

	if guestResult.Success {
		guestAllowed = true
		guestAttempt.Message = "Guest authentication successful"
		// If no other connection succeeded, use guest connection
		if !connectionSuccessful {
			connectionSuccessful = true
			workingClient = guestResult.Client
			if guestResult.ServerInfo != nil {
				serverInfo = guestResult.ServerInfo
			}
		} else {
			_ = guestResult.Client.Close() // Close guest connection since we have a working one
		}
	} else {
		guestAttempt.Message = guestResult.Error.Error()
		// Extract server info even if connection failed (from NTLM challenge)
		if serverInfo == nil && guestResult.ServerInfo != nil {
			serverInfo = guestResult.ServerInfo
		}
		_ = guestResult.Client.Close()
	}
	authAttempts = append(authAttempts, guestAttempt)

	// Set the working client as our primary client for share enumeration
	if connectionSuccessful && workingClient != nil {
		client = workingClient
	}

	// If all connections failed, log the error
	if !connectionSuccessful {
		errors = append(errors, fmt.Sprintf("All connection methods failed for %s", target))
	}

	// Close the connection at the very end after all operations are complete
	defer func() { _ = client.Close() }()

	// Set SMB version information and server info
	if serverInfo != nil {
		smbServerInfo := convertToSmbServerInfo(serverInfo)
		details.ServerInfo = smbServerInfo
		log.Info("Extracted server info",
			svc1log.SafeParam("target", target),
			svc1log.SafeParam("server", serverInfo.ServerName),
			svc1log.SafeParam("domain", serverInfo.Domain),
			svc1log.SafeParam("os", serverInfo.OSVersion),
			svc1log.SafeParam("signingRequired", serverInfo.SigningRequired))

		// Set supported versions from server capabilities if available
		if len(serverInfo.SupportedVersions) > 0 {
			var smbVersions []smb.SmbVersion
			for _, version := range serverInfo.SupportedVersions {
				if smbVersion, ok := smbclient.MapProtocolVersionToEnum(version); ok {
					smbVersions = append(smbVersions, smbVersion)
				}
			}
			if len(smbVersions) > 0 {
				details.SupportedVersions = smbVersions
				// Use the first (highest) supported version as the primary version
				details.Version = &smbVersions[0]
			}
		}
	}

	// Set defaults if server info wasn't available or didn't have version info
	if details.Version == nil {
		version := smb.SmbVersionSmb302
		details.Version = &version
	}
	if len(details.SupportedVersions) == 0 {
		details.SupportedVersions = []smb.SmbVersion{
			smb.SmbVersionSmb302,
			smb.SmbVersionSmb30,
			smb.SmbVersionSmb21,
			smb.SmbVersionSmb20,
		}
	}

	// Enumerate shares using the protocol library (only if we have a successful connection)
	if connectionSuccessful {
		log.Info("Enumerating shares", svc1log.SafeParam("target", target))
		shares, shareErr := client.EnumerateSharesWithContext(ctx)
		if shareErr != nil {
			errors = append(errors, fmt.Sprintf("Share enumeration failed: %v", shareErr))
		}

		if len(shares) > 0 {
			smbShares := convertToSmbShares(shares)
			details.Shares = smbShares
			log.Info("Found shares",
				svc1log.SafeParam("shareCount", len(shares)),
				svc1log.SafeParam("target", target))
		}
	}

	// Set authentication method information
	authMethods := []smb.AuthMethod{smb.AuthMethodNtlm}
	details.AuthMethods = authMethods

	// Authentication capabilities are already determined above

	details.AnonymousLoginAllowed = &anonymousAllowed
	details.GuestLoginAllowed = &guestAllowed
	details.NullSessionAllowed = &nullSessionAllowed

	// Set authentication attempts
	details.AuthAttempts = authAttempts

	// Set security settings from server info
	if serverInfo != nil {
		details.SigningRequired = &serverInfo.SigningRequired
	}

	// Set raw response information
	rawResponse := fmt.Sprintf("SMB2 Connection - Signing: %v",
		serverInfo != nil && serverInfo.SigningRequired)
	details.RawResponse = &rawResponse

	log.Info("SMB enumeration completed", svc1log.SafeParam("target", target))

	return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSmbDetails(&details), errors
}

// convertToSmbServerInfo converts protocol library ServerInfo to fern ServerInfo
func convertToSmbServerInfo(serverInfo *smbclient.ServerInfo) *smb.ServerInfo {
	if serverInfo == nil {
		return nil
	}

	return &smb.ServerInfo{
		ServerName:   &serverInfo.ServerName,
		Domain:       &serverInfo.Domain,
		OsVersion:    &serverInfo.OSVersion,
		Capabilities: serverInfo.Capabilities,
	}
}

// convertToSmbShares converts protocol library ShareInfo to fern SmbShare
func convertToSmbShares(shares []*smbclient.ShareInfo) []*smb.SmbShare {
	var smbShares []*smb.SmbShare

	for _, share := range shares {
		shareType := convertShareType(share.Type)
		shareAccess := convertShareAccess(share.Access)

		smbShare := &smb.SmbShare{
			Name:            share.Name,
			Type:            shareType,
			Accessible:      share.Accessible,
			Access:          &shareAccess,
			AnonymousAccess: share.AnonymousAccess,
			GuestAccess:     share.GuestAccess,
		}

		smbShares = append(smbShares, smbShare)
	}

	return smbShares
}

// convertShareType converts string share type to fern ShareType
func convertShareType(shareType string) smb.ShareType {
	switch shareType {
	case "IPC":
		return smb.ShareTypeIpc
	case "Print":
		return smb.ShareTypePrint
	case "Disk":
		return smb.ShareTypeDisk
	default:
		return smb.ShareTypeDisk
	}
}

// convertShareAccess converts string share access to fern ShareAccess
func convertShareAccess(access string) smb.ShareAccess {
	switch access {
	case "Read":
		return smb.ShareAccessReadOnly
	case "Write", "Full":
		return smb.ShareAccessReadWrite
	default:
		return smb.ShareAccessNoAccess
	}
}
