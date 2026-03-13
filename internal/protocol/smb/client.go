package smb

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	"github.com/Method-Security/networkscan/internal/common/ntlm"
	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/ntlmssp"
	gosmb "github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/spnego"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// ErrChallengeReceived is a sentinel error indicating the NTLM challenge was successfully received
var ErrChallengeReceived = errors.New("challenge_received")

// CapturingNTLM wraps the built-in NTLM initiator and captures the server's challenge
type CapturingNTLM struct {
	*spnego.NTLMInitiator
	LastChallenge     *ntlmssp.Challenge
	LastChallengeData []byte
}

// ChallengeOnlyNTLM only performs the challenge exchange and then stops
type ChallengeOnlyNTLM struct {
	*spnego.NTLMInitiator
	LastChallenge     *ntlmssp.Challenge
	LastChallengeData []byte
	challengeReceived bool
}

func (c *CapturingNTLM) InitSecContext(inputToken []byte) ([]byte, error) {
	// When the server replies to our first token, inputToken contains a SPNEGO NegTokenResp
	// whose ResponseToken is the NTLM Type 2 CHALLENGE.
	if len(inputToken) > 0 {
		// Try to parse as SPNEGO first
		var resp gss.NegTokenResp
		var meta encoder.Metadata
		if err := resp.UnmarshalBinary(inputToken, &meta); err == nil && len(resp.ResponseToken) > 0 {
			// Store the raw challenge data for unified processing
			c.LastChallengeData = resp.ResponseToken
		} else {
			// If SPNEGO parsing fails, check if this is a direct NTLM challenge
			// NTLM Type 2 messages start with "NTLMSSP\x00" (signature) followed by type 02
			if len(inputToken) >= 12 && string(inputToken[:8]) == "NTLMSSP\x00" {
				// Check for Type 2 message (challenge)
				if inputToken[8] == 0x02 && inputToken[9] == 0x00 && inputToken[10] == 0x00 && inputToken[11] == 0x00 {
					c.LastChallengeData = inputToken
				}
			}
		}

		// Try to parse the challenge for validation
		if len(c.LastChallengeData) > 0 {
			ch := ntlmssp.NewChallenge()
			if err := encoder.Unmarshal(c.LastChallengeData, &ch); err == nil {
				c.LastChallenge = &ch
			}
		}
	}
	return c.NTLMInitiator.InitSecContext(inputToken)
}

func (c *ChallengeOnlyNTLM) InitSecContext(inputToken []byte) ([]byte, error) {
	// When the server replies to our first token, inputToken contains a SPNEGO NegTokenResp
	// whose ResponseToken is the NTLM Type 2 CHALLENGE.
	if len(inputToken) > 0 && !c.challengeReceived {
		// Try to parse as SPNEGO first
		var resp gss.NegTokenResp
		var meta encoder.Metadata
		if err := resp.UnmarshalBinary(inputToken, &meta); err == nil && len(resp.ResponseToken) > 0 {
			// Store the raw challenge data for unified processing
			c.LastChallengeData = resp.ResponseToken
			c.challengeReceived = true
		} else {
			// If SPNEGO parsing fails, check if this is a direct NTLM challenge
			// NTLM Type 2 messages start with "NTLMSSP\x00" (signature) followed by type 02
			if len(inputToken) >= 12 && string(inputToken[:8]) == "NTLMSSP\x00" {
				// Check for Type 2 message (challenge)
				if inputToken[8] == 0x02 && inputToken[9] == 0x00 && inputToken[10] == 0x00 && inputToken[11] == 0x00 {
					c.LastChallengeData = inputToken
					c.challengeReceived = true
				}
			}
		}

		// Try to parse the challenge for validation
		if len(c.LastChallengeData) > 0 {
			ch := ntlmssp.NewChallenge()
			if err := encoder.Unmarshal(c.LastChallengeData, &ch); err == nil {
				c.LastChallenge = &ch
			}
		}

		// If we've received a challenge, stop the authentication process
		if c.challengeReceived {
			return nil, ErrChallengeReceived // Special error to signal we got what we wanted
		}
	}

	// For the initial request, proceed normally
	return c.NTLMInitiator.InitSecContext(inputToken)
}

// Client represents a unified SMB client that provides base functionality
// for both enumeration and pentest operations
type Client struct {
	Host            string
	Port            int
	Username        string
	Password        string
	NTLMHash        string // NTLM hash for pass-the-hash authentication
	Domain          string
	LocalAuth       bool // If true, force local auth (don't use domain from server challenge)
	UseAnonymous    bool
	UseNullSession  bool
	ChallengeOnly   bool // If true, only get NTLM challenge and exit without authentication
	Timeout         time.Duration
	session         *gosmb.Connection
	isConnected     bool
	isAuthenticated bool
	capturingNTLM   *CapturingNTLM
	serverInfo      *commonprotocolfern.SmbServerInfo
	skipServerInfo  bool // If true, skip automatic server info extraction on connect
}

// NewClient creates a new SMB client with the given configuration
func NewClient(host string, port int) *Client {
	if port == 0 {
		port = 445 // Default SMB port
	}

	// Wrap bare IPv6 addresses in brackets so the go-smb library's
	// fmt.Sprintf("%s:%d", host, port) produces a valid dial address.
	// net.ParseIP handles standard IPv6; the zone-scoped check (contains ":"
	// but not bracketed) catches addresses like fe80::1%eth0.
	if !strings.HasPrefix(host, "[") && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}

	return &Client{
		Host:    host,
		Port:    port,
		Timeout: 30 * time.Second,
	}
}

// SetCredentials sets username and password for authentication
func (c *Client) SetCredentials(username, password, domain string) {
	c.Username = username
	c.Password = password
	c.NTLMHash = "" // Clear hash when setting password
	c.Domain = domain
	c.UseAnonymous = false
	c.UseNullSession = false
}

// SetCredentialsWithHash sets username and NTLM hash for pass-the-hash authentication
func (c *Client) SetCredentialsWithHash(username, ntlmHash, domain string) {
	c.Username = username
	c.Password = "" // Clear password when setting hash
	c.NTLMHash = ntlmHash
	c.Domain = domain
	c.UseAnonymous = false
	c.UseNullSession = false
}

// SetAnonymous configures client for anonymous authentication
func (c *Client) SetAnonymous() {
	c.UseAnonymous = true
	c.UseNullSession = false
	c.Username = ""
	c.Password = ""
}

// SetNullSession configures client for null session authentication
func (c *Client) SetNullSession() {
	c.UseNullSession = true
	c.UseAnonymous = false
	c.Username = ""
	c.Password = ""
}

// SetChallengeOnly configures client to only retrieve NTLM challenge without authentication
func (c *Client) SetChallengeOnly() {
	c.ChallengeOnly = true
	c.UseAnonymous = true // Use anonymous for challenge retrieval
	c.UseNullSession = false
	c.Username = ""
	c.Password = ""
}

// Connect establishes connection to SMB server and performs authentication
func (c *Client) Connect() error {
	return c.ConnectWithContext(context.Background())
}

// ExtractServerInfoFromChallenge attempts to extract server information from NTLM challenge
// This works even when authentication fails, as the challenge contains server metadata
func (c *Client) ExtractServerInfoFromChallenge(ctx context.Context) (*commonprotocolfern.SmbServerInfo, error) {
	log := svc1log.FromContext(ctx)
	log.Debug("Starting ExtractServerInfoFromChallenge using unified NTLM challenge parser", svc1log.SafeParam("host", c.Host), svc1log.SafeParam("port", c.Port))

	// Check if we have captured challenge data from a previous connection attempt
	if c.capturingNTLM == nil || c.capturingNTLM.LastChallengeData == nil {
		return nil, fmt.Errorf("no NTLM challenge data available for server info extraction")
	}

	// Use unified NTLM challenge parser
	ntlmInfo, err := ntlm.ExtractServerInfoFromChallenge(c.capturingNTLM.LastChallengeData, log)
	if err != nil {
		return nil, fmt.Errorf("failed to extract server info from NTLM challenge: %v", err)
	}

	// Convert to SMB-specific server info with additional fields
	smbInfo := convertNtlmToSmbServerInfo(ntlmInfo)

	// Set SMB-specific signing fields based on server's security mode (not session state)
	if c.session != nil {
		// Use reflection to get the server's actual security mode from the negotiate response
		// This is necessary because IsSigningRequired() returns session-level state, which is
		// set to false for null/guest sessions even when the server requires signing
		securityMode, err := c.getServerSecurityMode()
		if err != nil {
			log.Debug("Failed to get server security mode, falling back to session signing state",
				svc1log.SafeParam("error", err))
			// Fallback to session-level signing state
			signingRequired := c.session.IsSigningRequired()
			smbInfo.SigningRequired = &signingRequired
		} else {
			// Successfully got server security mode - parse the flags
			// SecurityModeSigningRequired = 2
			signingRequired := (securityMode & gosmb.SecurityModeSigningRequired) > 0
			smbInfo.SigningRequired = &signingRequired

			log.Debug("Server security mode retrieved",
				svc1log.SafeParam("securityMode", securityMode),
				svc1log.SafeParam("signingRequired", signingRequired))
		}
	}

	// SMB version detection - would need actual negotiation data
	smbInfo.SmbVersion = nil                                         // Set when we have negotiation info
	smbInfo.SupportedSmbVersions = []commonprotocolfern.SmbVersion{} // Set when we have negotiation info

	log.Debug("Successfully extracted server info from unified NTLM challenge parser",
		svc1log.SafeParam("mappedOsVersion", smbInfo.MappedOsVersion))

	return smbInfo, nil
}

// GetDomainFromServerInfo extracts domain information from server info for authentication
func (c *Client) GetDomainFromServerInfo(ctx context.Context) string {
	serverInfo, err := c.ExtractServerInfoFromChallenge(ctx)
	if err != nil || serverInfo == nil || serverInfo.TargetInfo == nil {
		return ""
	}
	if serverInfo.TargetInfo.DnsDomainName != nil {
		return *serverInfo.TargetInfo.DnsDomainName
	}
	if serverInfo.TargetInfo.NetbiosDomainName != nil {
		return *serverInfo.TargetInfo.NetbiosDomainName
	}
	return ""
}

// ConnectWithContext establishes connection to SMB server and performs authentication with context
func (c *Client) ConnectWithContext(ctx context.Context) error {
	if c.isConnected {
		return nil
	}

	// Create SMB connection options (matching go-secdump defaults)
	options := gosmb.Options{
		Host:              c.Host,
		Port:              c.Port,
		DialTimeout:       c.Timeout,
		DisableEncryption: false, // Allow encryption (key fix)
		// Remove workstation name that might be filtered
	}

	// Set up authentication based on configuration
	var ntlmInitiator *spnego.NTLMInitiator

	if c.UseNullSession {
		ntlmInitiator = &spnego.NTLMInitiator{
			NullSession: true,
		}
	} else if c.UseAnonymous {
		ntlmInitiator = &spnego.NTLMInitiator{
			User:     "",
			Password: "",
		}
	} else if c.Username != "" || c.Password != "" || c.NTLMHash != "" {
		// Set up NTLM authentication with password or hash
		ntlmInitiator = &spnego.NTLMInitiator{
			User:      c.Username,
			Domain:    c.Domain,
			LocalUser: c.LocalAuth,
		}

		// Use hash if available, otherwise use password
		if c.NTLMHash != "" {
			processor := ntlm.NewHashProcessor()
			ntHash, err := processor.ParseNTLMHash(c.NTLMHash)
			if err != nil {
				return fmt.Errorf("failed to process NTLM hash for SMB: %v", err)
			}

			// Debug logging
			log := svc1log.FromContext(ctx)
			log.Debug("NTLM hash processing",
				svc1log.SafeParam("originalHash", c.NTLMHash),
				svc1log.SafeParam("ntHashLength", len(ntHash)),
				svc1log.SafeParam("username", ntlmInitiator.User),
				svc1log.SafeParam("domain", ntlmInitiator.Domain))

			// Set only the NT hash (16 bytes)
			ntlmInitiator.Hash = ntHash
		} else {
			ntlmInitiator.Password = c.Password
		}
	} else {
		// Default to null session if no credentials provided
		ntlmInitiator = &spnego.NTLMInitiator{
			NullSession: true,
		}
	}

	// Wrap the NTLM initiator with appropriate wrapper to get raw challenge data
	var challengeOnlyWrapper *ChallengeOnlyNTLM
	if c.ChallengeOnly {
		// Use challenge-only wrapper for stealth mode
		challengeOnlyWrapper = &ChallengeOnlyNTLM{
			NTLMInitiator: ntlmInitiator,
		}
		options.Initiator = challengeOnlyWrapper
	} else {
		// Use regular capturing wrapper
		c.capturingNTLM = &CapturingNTLM{
			NTLMInitiator: ntlmInitiator,
		}
		options.Initiator = c.capturingNTLM
	}

	// Attempt connection
	session, err := gosmb.NewConnection(options)

	// For challenge-only mode, transfer data and handle the expected error
	if c.ChallengeOnly && challengeOnlyWrapper != nil {
		// Create capturing NTLM with the challenge data from challenge-only wrapper
		c.capturingNTLM = &CapturingNTLM{
			NTLMInitiator:     ntlmInitiator,
			LastChallenge:     challengeOnlyWrapper.LastChallenge,
			LastChallengeData: challengeOnlyWrapper.LastChallengeData,
		}

		// Check if we got the expected "challenge_received" error, which means success for us
		if err != nil && (errors.Is(err, ErrChallengeReceived) || strings.Contains(err.Error(), "challenge_received")) {
			log := svc1log.FromContext(ctx)
			log.Debug("Successfully received NTLM challenge in stealth mode")

			// Store the session so we can access security mode via reflection
			if session != nil {
				c.session = session
			}

			// Extract server info and return success
			if !c.skipServerInfo {
				serverInfo, extractErr := c.ExtractServerInfoFromChallenge(ctx)
				if extractErr != nil {
					log.Debug("Failed to extract server info from challenge, using fallback", svc1log.SafeParam("error", extractErr))
					c.serverInfo = c.createFallbackServerInfo(ctx)
				} else {
					c.serverInfo = serverInfo
				}
			}

			// For challenge-only mode, getting the challenge is success
			c.isConnected = false     // We didn't actually establish a connection
			c.isAuthenticated = false // We didn't authenticate
			return nil                // Success - we got what we wanted
		}
	}

	if err != nil {
		// Even if connection failed, try to extract server info from NTLM challenge (unless skipped)
		if session != nil && !c.skipServerInfo {
			c.session = session
			// Use the existing server info extraction logic
			serverInfo, extractErr := c.ExtractServerInfoFromChallenge(ctx)
			if extractErr != nil {
				log := svc1log.FromContext(ctx)
				log.Debug("Failed to extract server info from failed connection, using fallback", svc1log.SafeParam("error", extractErr))
				c.serverInfo = c.createFallbackServerInfo(ctx)
			} else {
				c.serverInfo = serverInfo
			}
		}
		return fmt.Errorf("failed to connect to SMB server %s:%d: %v", c.Host, c.Port, err)
	}

	c.session = session
	c.isConnected = true
	c.isAuthenticated = session.IsAuthenticated()

	log := svc1log.FromContext(ctx)
	log.Info("SMB connection established",
		svc1log.SafeParam("host", c.Host),
		svc1log.SafeParam("port", c.Port),
		svc1log.SafeParam("authenticated", c.isAuthenticated))

	// Extract server information (unless skipped)
	if !c.skipServerInfo {
		serverInfo, extractErr := c.ExtractServerInfoFromChallenge(ctx)
		if extractErr != nil {
			log.Warn("Failed to extract server info, using fallback", svc1log.SafeParam("error", extractErr))
			c.serverInfo = c.createFallbackServerInfo(ctx)
		} else {
			c.serverInfo = serverInfo
		}
	}

	return nil
}

// IsConnected returns true if client is connected to SMB server
func (c *Client) IsConnected() bool {
	return c.isConnected
}

// IsAuthenticated returns true if client is authenticated to SMB server
func (c *Client) IsAuthenticated() bool {
	return c.isAuthenticated
}

// GetServerInfo returns extracted server information
func (c *Client) GetServerInfo() *commonprotocolfern.SmbServerInfo {
	return c.serverInfo
}

// SetServerInfo sets server info from external source (to avoid redundant extraction)
func (c *Client) SetServerInfo(serverInfo *commonprotocolfern.SmbServerInfo) {
	c.serverInfo = serverInfo
}

// SkipServerInfoExtraction configures whether to skip automatic server info extraction on connect
func (c *Client) SkipServerInfoExtraction(skip bool) {
	c.skipServerInfo = skip
}

// TestCredentials tests if the provided credentials are valid
func (c *Client) TestCredentials(username, password, domain string) (bool, string, error) {
	// Create temporary client for credential testing
	testClient := NewClient(c.Host, c.Port)
	testClient.SetCredentials(username, password, domain)
	testClient.Timeout = c.Timeout

	err := testClient.Connect()
	if err != nil {
		func() {
			defer func() { _ = recover() }()
			_ = testClient.Close()
		}()
		// Analyze error for specific failure types
		errStr := err.Error()

		if strings.Contains(errStr, "STATUS_LOGON_FAILURE") {
			return false, "STATUS_LOGON_FAILURE", nil
		}
		if strings.Contains(errStr, "STATUS_PASSWORD_EXPIRED") {
			return false, "STATUS_PASSWORD_EXPIRED", nil
		}
		if strings.Contains(errStr, "STATUS_ACCOUNT_LOCKED_OUT") {
			return false, "STATUS_ACCOUNT_LOCKED_OUT", nil
		}
		if strings.Contains(errStr, "STATUS_ACCOUNT_DISABLED") {
			return false, "STATUS_ACCOUNT_DISABLED", nil
		}
		if strings.Contains(errStr, "STATUS_LOGON_TYPE_NOT_GRANTED") {
			return false, "STATUS_LOGON_TYPE_NOT_GRANTED", nil
		}

		return false, "", err
	}

	defer func() { _ = testClient.Close() }()

	if testClient.IsAuthenticated() {
		authUser := testClient.session.GetAuthUsername()
		return true, fmt.Sprintf("Authentication successful as %s", authUser), nil
	}

	return false, "Authentication failed", nil
}

// EnumerateShares lists available shares using TreeConnect testing
func (c *Client) EnumerateShares() ([]*commonprotocolfern.SmbShare, error) {
	return c.EnumerateSharesWithContext(context.Background())
}

// EnumerateSharesWithContext lists available shares using TreeConnect testing with context
func (c *Client) EnumerateSharesWithContext(ctx context.Context) ([]*commonprotocolfern.SmbShare, error) {
	if !c.isConnected {
		return nil, fmt.Errorf("not connected to SMB server")
	}

	commonShares := []string{"C$", "D$", "E$", "ADMIN$", "IPC$", "PRINT$", "FAX$", "SYSVOL", "NETLOGON", "Users", "Public", "Share", "Data", "Files", "Shared", "Transfer", "Backup", "Archive", "Home", "Homes"}
	var shares []*commonprotocolfern.SmbShare

	log := svc1log.FromContext(ctx)
	log.Info("Testing common share names for accessibility", svc1log.SafeParam("shareCount", len(commonShares)))

	for _, shareName := range commonShares {
		shareType := c.determineShareType(shareName)
		accessible := false
		access := commonprotocolfern.ShareAccessNoAccess
		anonymousAccess := c.UseAnonymous || c.UseNullSession
		guestAccess := false
		hidden := strings.HasSuffix(shareName, "$")

		shareInfo := &commonprotocolfern.SmbShare{
			Name:            shareName,
			Type:            shareType,
			Accessible:      &accessible,
			Access:          &access,
			AnonymousAccess: &anonymousAccess,
			GuestAccess:     &guestAccess,
			Hidden:          &hidden,
		}

		// Test share accessibility
		err := c.session.TreeConnect(shareName)
		if err == nil {
			// Share is accessible
			accessible = true
			access = commonprotocolfern.ShareAccessReadOnly // Assume read access if TreeConnect succeeded
			shareInfo.Accessible = &accessible
			shareInfo.Access = &access
			_ = c.session.TreeDisconnect(shareName)
		}

		shares = append(shares, shareInfo)
	}

	accessibleCount := 0
	for _, share := range shares {
		if share.Accessible != nil && *share.Accessible {
			accessibleCount++
		}
	}

	log.Info("Share enumeration completed",
		svc1log.SafeParam("totalShares", len(shares)),
		svc1log.SafeParam("accessibleShares", accessibleCount))
	return shares, nil
}

// Close closes the SMB connection
func (c *Client) Close() error {
	if c.session != nil {
		c.session.Close()
		c.isConnected = false
		c.isAuthenticated = false
	}
	return nil
}

// SafeClose closes the client with panic recovery.
// The underlying go-smb library can panic during Close() in certain states.
func (c *Client) SafeClose() {
	if c == nil {
		return
	}
	defer func() { _ = recover() }()
	_ = c.Close()
}

// determineShareType determines the share type based on share name patterns
func (c *Client) determineShareType(shareName string) commonprotocolfern.ShareType {
	switch {
	case shareName == "IPC$":
		return commonprotocolfern.ShareTypeIpc
	case shareName == "PRINT$" || shareName == "FAX$":
		return commonprotocolfern.ShareTypePrint
	case strings.HasSuffix(shareName, "$"):
		return commonprotocolfern.ShareTypeDisk // Administrative shares
	default:
		return commonprotocolfern.ShareTypeDisk // Regular disk shares
	}
}

// GetSMBSession returns the underlying go-smb connection for DCE/RPC operations
func (c *Client) GetSMBSession() (*gosmb.Connection, error) {
	if !c.isConnected || c.session == nil {
		return nil, fmt.Errorf("no active SMB session")
	}
	return c.session, nil
}

// getServerSecurityMode uses reflection to access the unexported securityMode field
// from the SMB negotiate response. This is necessary because the session's IsSigningRequired()
// returns false for null/guest sessions even when the server requires signing.
//
// The securityMode field is set from the SMB negotiate response and contains the server's
// actual signing configuration. The session's IsSigningRequired() method returns the session-level
// requirement, which is forcibly set to false for guest/null sessions regardless of the server
// configuration.
func (c *Client) getServerSecurityMode() (uint16, error) {
	if c.session == nil {
		return 0, fmt.Errorf("no active SMB session")
	}

	// Use reflection to access the unexported securityMode field from the embedded Session struct
	sessionValue := reflect.ValueOf(c.session).Elem()
	securityModeField := sessionValue.FieldByName("securityMode")

	if !securityModeField.IsValid() {
		return 0, fmt.Errorf("securityMode field not found in SMB session - library structure may have changed")
	}

	// Get the uint16 value
	securityMode := securityModeField.Uint()
	return uint16(securityMode), nil
}

// createFallbackServerInfo creates minimal server info when extraction fails
func (c *Client) createFallbackServerInfo(ctx context.Context) *commonprotocolfern.SmbServerInfo {
	log := svc1log.FromContext(ctx)

	if c.session == nil {
		return nil
	}

	// Create minimal server info with default supported versions
	serverInfo := &commonprotocolfern.SmbServerInfo{
		SupportedSmbVersions: []commonprotocolfern.SmbVersion{
			commonprotocolfern.SmbVersionSmb302,
			commonprotocolfern.SmbVersionSmb30,
			commonprotocolfern.SmbVersionSmb21,
			commonprotocolfern.SmbVersionSmb20,
		},
	}

	// Try to get server security mode from negotiate response using reflection
	securityMode, err := c.getServerSecurityMode()
	if err != nil {
		log.Debug("Failed to get server security mode in fallback path, using session signing state",
			svc1log.SafeParam("error", err))
		// Fallback to session-level signing state
		signingRequired := c.session.IsSigningRequired()
		serverInfo.SigningRequired = &signingRequired
	} else {
		// Parse security mode flags
		signingRequired := (securityMode & gosmb.SecurityModeSigningRequired) > 0
		serverInfo.SigningRequired = &signingRequired
	}

	return serverInfo
}

// convertNtlmToSmbServerInfo converts NtlmServerInfo to SmbServerInfo, preserving nested structures
func convertNtlmToSmbServerInfo(ntlmInfo *commonprotocolfern.NtlmServerInfo) *commonprotocolfern.SmbServerInfo {
	return &commonprotocolfern.SmbServerInfo{
		MappedOsVersion:      ntlmInfo.MappedOsVersion,
		TargetInfo:           ntlmInfo.TargetInfo,
		OsInfo:               ntlmInfo.OsInfo,
		SmbVersion:           nil,                               // SMB-specific field, set separately
		SupportedSmbVersions: []commonprotocolfern.SmbVersion{}, // SMB-specific field, set separately
		SigningRequired:      nil,                               // SMB-specific field, set separately
		EncryptionSupported:  nil,                               // SMB-specific field, set separately
		EncryptionRequired:   nil,                               // SMB-specific field, set separately
		LanManagerVersion:    nil,                               // SMB-specific field, set separately
	}
}
