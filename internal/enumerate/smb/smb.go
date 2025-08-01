package smb

import (
	"context"
	"fmt"
	"time"

	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	smb "github.com/Method-Security/networkscan/generated/go/enumerate/smb"
	smbclient "github.com/Method-Security/networkscan/internal/protocol/smb"
	"github.com/Method-Security/networkscan/utils"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumerateSMB implements NetworkApplicationLibrary for SMB enumeration using the shared protocol library.
type LibraryEnumerateSMB struct{}

// authTestResult holds the result of an authentication test
type authTestResult struct {
	success       bool
	client        *smbclient.Client
	serverInfo    *smbclient.ServerInfo
	authAttempt   *commonprotocolfern.SmbAuthAttempt
	allowedMethod bool
}

// testNullSession tests null session authentication
func (s *LibraryEnumerateSMB) testNullSession(ctx context.Context, host string, port int, target string) authTestResult {
	nullResult := smbclient.TestConnectionMethod(ctx, host, port,
		func(c *smbclient.Client) { c.SetNullSession() },
		"Null session", target)

	result := authTestResult{
		success:       nullResult.Success,
		client:        nullResult.Client,
		serverInfo:    nullResult.ServerInfo,
		allowedMethod: nullResult.Success,
	}

	return result
}

// testAnonymousSession tests anonymous authentication
func (s *LibraryEnumerateSMB) testAnonymousSession(ctx context.Context, host string, port int, target string) authTestResult {
	anonResult := smbclient.TestConnectionMethod(ctx, host, port,
		func(c *smbclient.Client) { c.SetAnonymous() },
		"Anonymous login", target)

	result := authTestResult{
		success:       anonResult.Success,
		client:        anonResult.Client,
		serverInfo:    anonResult.ServerInfo,
		allowedMethod: anonResult.Success,
	}

	return result
}

// testGuestAuthentication tests guest authentication and creates auth attempt record
func (s *LibraryEnumerateSMB) testGuestAuthentication(ctx context.Context, host string, port int, target string) authTestResult {
	guestResult := smbclient.TestConnectionMethod(ctx, host, port,
		func(c *smbclient.Client) { c.SetCredentials("guest", "", "") },
		"Guest authentication", target)

	authAttempt := &commonprotocolfern.SmbAuthAttempt{
		Username:  "guest",
		Password:  "",
		Success:   guestResult.Success,
		Timestamp: time.Now(),
	}

	if guestResult.Success {
		authAttempt.Message = "Guest authentication successful"
	} else {
		authAttempt.Message = guestResult.Error.Error()
	}

	result := authTestResult{
		success:       guestResult.Success,
		client:        guestResult.Client,
		serverInfo:    guestResult.ServerInfo,
		authAttempt:   authAttempt,
		allowedMethod: guestResult.Success,
	}

	return result
}

// authenticationState holds the collective results of all authentication tests
type authenticationState struct {
	serverInfo           *smbclient.ServerInfo
	authAttempts         []*commonprotocolfern.SmbAuthAttempt
	nullSessionAllowed   bool
	anonymousAllowed     bool
	guestAllowed         bool
	connectionSuccessful bool
	workingClient        *smbclient.Client
}

// performAuthentication tests all authentication methods and returns the collective state
func (s *LibraryEnumerateSMB) performAuthentication(ctx context.Context, host string, port int, target string) authenticationState {
	var state authenticationState

	// Test null session first
	nullResult := s.testNullSession(ctx, host, port, target)
	state.nullSessionAllowed = nullResult.allowedMethod

	if nullResult.success {
		state.connectionSuccessful = true
		state.workingClient = nullResult.client
		if nullResult.serverInfo != nil {
			state.serverInfo = nullResult.serverInfo
		}
	} else {
		// Extract server info even if connection failed (from NTLM challenge)
		if state.serverInfo == nil && nullResult.serverInfo != nil {
			state.serverInfo = nullResult.serverInfo
		}
		_ = nullResult.client.Close()
	}

	// Test anonymous connection if null session failed
	if !state.connectionSuccessful {
		anonResult := s.testAnonymousSession(ctx, host, port, target)
		state.anonymousAllowed = anonResult.allowedMethod

		if anonResult.success {
			state.connectionSuccessful = true
			state.workingClient = anonResult.client
			if anonResult.serverInfo != nil {
				state.serverInfo = anonResult.serverInfo
			}
		} else {
			// Extract server info even if connection failed (from NTLM challenge)
			if state.serverInfo == nil && anonResult.serverInfo != nil {
				state.serverInfo = anonResult.serverInfo
			}
			_ = anonResult.client.Close()
		}
	}

	// Test guest authentication (this is a real credential-based auth attempt)
	// We test this separately to record the auth attempt
	guestResult := s.testGuestAuthentication(ctx, host, port, target)
	state.guestAllowed = guestResult.allowedMethod
	state.authAttempts = append(state.authAttempts, guestResult.authAttempt)

	if guestResult.success {
		// If no other connection succeeded, use guest connection
		if !state.connectionSuccessful {
			state.connectionSuccessful = true
			state.workingClient = guestResult.client
			if guestResult.serverInfo != nil {
				state.serverInfo = guestResult.serverInfo
			}
		} else {
			_ = guestResult.client.Close() // Close guest connection since we have a working one
		}
	} else {
		// Extract server info even if connection failed (from NTLM challenge)
		if state.serverInfo == nil && guestResult.serverInfo != nil {
			state.serverInfo = guestResult.serverInfo
		}
		_ = guestResult.client.Close()
	}

	return state
}

// processServerInfo sets up server info and SMB version details in the response
func (s *LibraryEnumerateSMB) processServerInfo(serverInfo *smbclient.ServerInfo, details *smb.EnumerateSmbDetails, target string, log svc1log.Logger) {
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
			var smbVersions []commonprotocolfern.SmbVersion
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
		version := commonprotocolfern.SmbVersionSmb302
		details.Version = &version
	}
	if len(details.SupportedVersions) == 0 {
		details.SupportedVersions = []commonprotocolfern.SmbVersion{
			commonprotocolfern.SmbVersionSmb302,
			commonprotocolfern.SmbVersionSmb30,
			commonprotocolfern.SmbVersionSmb21,
			commonprotocolfern.SmbVersionSmb20,
		}
	}
}

// enumerateShares performs share enumeration if connection is successful
func (s *LibraryEnumerateSMB) enumerateShares(ctx context.Context, client *smbclient.Client, connectionSuccessful bool, details *smb.EnumerateSmbDetails, target string, log svc1log.Logger) []string {
	var errors []string

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

	return errors
}

// assembleResponse builds the final enumeration response
func (s *LibraryEnumerateSMB) assembleResponse(details *smb.EnumerateSmbDetails, state authenticationState, serverInfo *smbclient.ServerInfo) {
	// Set authentication method information
	authMethods := []commonprotocolfern.AuthMethod{commonprotocolfern.AuthMethodNtlm}
	details.AuthMethods = authMethods

	// Set authentication capabilities
	details.AnonymousLoginAllowed = &state.anonymousAllowed
	details.GuestLoginAllowed = &state.guestAllowed
	details.NullSessionAllowed = &state.nullSessionAllowed

	// Set authentication attempts
	details.AuthAttempts = state.authAttempts

	// Set security settings from server info
	if serverInfo != nil {
		details.SigningRequired = &serverInfo.SigningRequired
	}

	// Set raw response information
	rawResponse := fmt.Sprintf("SMB2 Connection - Signing: %v",
		serverInfo != nil && serverInfo.SigningRequired)
	details.RawResponse = &rawResponse
}

// EnumerateTarget performs comprehensive SMB enumeration using the shared SMB protocol library
func (s *LibraryEnumerateSMB) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	var details smb.EnumerateSmbDetails
	details.Target = target
	var errors []string

	log := svc1log.FromContext(ctx)
	log.Info("Starting SMB enumeration for target", svc1log.SafeParam("target", target))

	host, port := utils.ParseHostPort(target, 445)

	// Create SMB client using shared protocol library
	client := smbclient.NewClient(host, port)

	// Perform all authentication tests
	authState := s.performAuthentication(ctx, host, port, target)

	// Set the working client as our primary client for share enumeration
	if authState.connectionSuccessful && authState.workingClient != nil {
		client = authState.workingClient
	}

	// If all connections failed, log the error
	if !authState.connectionSuccessful {
		errors = append(errors, fmt.Sprintf("All connection methods failed for %s", target))
	}

	// Close the connection at the very end after all operations are complete
	defer func() { _ = client.Close() }()

	// Process server info and set up SMB version details
	s.processServerInfo(authState.serverInfo, &details, target, log)

	// Enumerate shares
	shareErrors := s.enumerateShares(ctx, client, authState.connectionSuccessful, &details, target, log)
	errors = append(errors, shareErrors...)

	// Assemble the final response
	s.assembleResponse(&details, authState, authState.serverInfo)

	log.Info("SMB enumeration completed", svc1log.SafeParam("target", target))

	return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSmbDetails(&details), errors
}

// convertToSmbServerInfo converts protocol library ServerInfo to common SMB ServerInfo
func convertToSmbServerInfo(serverInfo *smbclient.ServerInfo) *commonprotocolfern.SmbServerInfo {
	if serverInfo == nil {
		return nil
	}

	result := &commonprotocolfern.SmbServerInfo{
		ServerName:        &serverInfo.ServerName,
		Domain:            &serverInfo.Domain,
		NetBiosDomainName: &serverInfo.NetBIOSDomainName,
		Workgroup:         &serverInfo.Domain, // Use domain as workgroup fallback
		OsVersion:         &serverInfo.OSVersion,
		Capabilities:      serverInfo.Capabilities,
		SigningRequired:   &serverInfo.SigningRequired,
	}

	// Include raw OS version if available
	if serverInfo.RawOSVersion != "" {
		result.RawOsVersion = &serverInfo.RawOSVersion
	}

	return result
}

// convertToSmbShares converts protocol library ShareInfo to common SMB Share
func convertToSmbShares(shares []*smbclient.ShareInfo) []*commonprotocolfern.SmbShare {
	var smbShares []*commonprotocolfern.SmbShare

	for _, share := range shares {
		shareType := convertShareType(share.Type)
		shareAccess := convertShareAccess(share.Access)

		smbShare := &commonprotocolfern.SmbShare{
			Name:            share.Name,
			Type:            shareType,
			Accessible:      share.Accessible,
			Access:          &shareAccess,
			AnonymousAccess: share.AnonymousAccess,
			GuestAccess:     share.GuestAccess,
			Hidden:          &share.Hidden,
		}

		if share.Comment != "" {
			smbShare.Comment = &share.Comment
		}

		smbShares = append(smbShares, smbShare)
	}

	return smbShares
}

// convertShareType converts string share type to common ShareType
func convertShareType(shareType string) commonprotocolfern.ShareType {
	switch shareType {
	case "IPC":
		return commonprotocolfern.ShareTypeIpc
	case "Print":
		return commonprotocolfern.ShareTypePrint
	case "Disk":
		return commonprotocolfern.ShareTypeDisk
	default:
		return commonprotocolfern.ShareTypeDisk
	}
}

// convertShareAccess converts string share access to common ShareAccess
func convertShareAccess(access string) commonprotocolfern.ShareAccess {
	switch access {
	case "Read":
		return commonprotocolfern.ShareAccessReadOnly
	case "Write", "Full":
		return commonprotocolfern.ShareAccessReadWrite
	default:
		return commonprotocolfern.ShareAccessNoAccess
	}
}
