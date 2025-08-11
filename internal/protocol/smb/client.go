package smb

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/internal/common"
	gosmb "github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// Client represents a unified SMB client that provides base functionality
// for both enumeration and pentest operations
type Client struct {
	Host            string
	Port            int
	Username        string
	Password        string
	NTLMHash        string // NTLM hash for pass-the-hash authentication
	Domain          string
	UseAnonymous    bool
	UseNullSession  bool
	Timeout         time.Duration
	session         *gosmb.Connection
	isConnected     bool
	isAuthenticated bool
	serverInfo      *ServerInfo
}

// ServerInfo contains basic server information extracted from SMB connection
type ServerInfo struct {
	ServerName        string
	Domain            string
	NetBIOSDomainName string
	OSVersion         string
	RawOSVersion      string
	ServerType        string
	Capabilities      []string
	SigningRequired   bool
	SupportedVersions []string
}

// ShareInfo represents SMB share information
type ShareInfo struct {
	Name            string
	Type            string
	Accessible      bool
	Access          string
	AnonymousAccess bool
	GuestAccess     bool
	Hidden          bool
	Comment         string
}

// NewClient creates a new SMB client with the given configuration
func NewClient(host string, port int) *Client {
	if port == 0 {
		port = 445 // Default SMB port
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

// Connect establishes connection to SMB server and performs authentication
func (c *Client) Connect() error {
	return c.ConnectWithContext(context.Background())
}

// ExtractServerInfoFromChallenge attempts to extract server information from NTLM challenge
// This works even when authentication fails, as the challenge contains server metadata
func (c *Client) ExtractServerInfoFromChallenge(ctx context.Context) (*ServerInfo, error) {
	log := svc1log.FromContext(ctx)
	log.Debug("Starting ExtractServerInfoFromChallenge using go-smb NTLM challenge", svc1log.SafeParam("host", c.Host), svc1log.SafeParam("port", c.Port))

	// If we don't have an existing session, try to establish one with null session
	if c.session == nil {
		// Set up null session temporarily
		originalNullSession := c.UseNullSession
		c.UseNullSession = true

		err := c.ConnectWithContext(ctx)
		if err != nil {
			log.Debug("Failed to establish null session for server info extraction", svc1log.SafeParam("error", err.Error()))
			// Even if connection failed, check if we got a session with target info
			if c.session == nil {
				return nil, fmt.Errorf("failed to establish session for server info extraction: %v", err)
			}
		}

		// Restore original null session setting
		c.UseNullSession = originalNullSession
	}

	// Extract target info from the NTLM challenge in current session
	targetInfo := c.session.GetTargetInfo()
	if targetInfo == nil {
		log.Debug("No target info available from NTLM challenge")
		return nil, fmt.Errorf("no target info available from NTLM challenge")
	}

	log.Debug("Successfully retrieved target info from NTLM challenge")

	// Convert go-smb TargetInfo to our ServerInfo structure
	serverInfo := &ServerInfo{
		SigningRequired: c.session.IsSigningRequired(),
	}

	// Extract server information from target info
	if targetInfo.DnsComputerName != "" {
		serverInfo.ServerName = targetInfo.DnsComputerName
	} else if targetInfo.NBComputerName != "" {
		serverInfo.ServerName = targetInfo.NBComputerName
	}

	if targetInfo.DnsDomainName != "" {
		serverInfo.Domain = targetInfo.DnsDomainName
	} else if targetInfo.NBDomainName != "" {
		serverInfo.Domain = targetInfo.NBDomainName
	}

	// Always set NetBIOS domain name if available
	if targetInfo.NBDomainName != "" {
		serverInfo.NetBIOSDomainName = targetInfo.NBDomainName
	}

	// Parse and enhance the OS version
	if targetInfo.GuessedOSVersion != "" {
		serverInfo.RawOSVersion = targetInfo.GuessedOSVersion
		serverInfo.OSVersion = parseWindowsVersion(targetInfo.GuessedOSVersion)
	} else {
		serverInfo.OSVersion = "Windows Server"
	}

	// Set capabilities based on actual server state
	var capabilities []string
	if serverInfo.SigningRequired {
		capabilities = append(capabilities, "Signing")
	}
	serverInfo.Capabilities = capabilities

	// SupportedVersions should be extracted from actual SMB negotiation, not hardcoded
	serverInfo.SupportedVersions = []string{}

	log.Debug("Successfully extracted server info from NTLM challenge",
		svc1log.SafeParam("serverName", serverInfo.ServerName),
		svc1log.SafeParam("domain", serverInfo.Domain),
		svc1log.SafeParam("osVersion", serverInfo.OSVersion))

	return serverInfo, nil
}

// GetDomainFromServerInfo extracts domain information from server info for authentication
func (c *Client) GetDomainFromServerInfo(ctx context.Context) string {
	serverInfo, err := c.ExtractServerInfoFromChallenge(ctx)
	if err != nil || serverInfo == nil {
		return ""
	}
	return serverInfo.Domain
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
	if c.UseNullSession {
		options.Initiator = &spnego.NTLMInitiator{
			NullSession: true,
		}
	} else if c.UseAnonymous {
		options.Initiator = &spnego.NTLMInitiator{
			User:     "",
			Password: "",
		}
	} else if c.Username != "" || c.Password != "" || c.NTLMHash != "" {
		// Set up NTLM authentication with password or hash
		ntlmInitiator := &spnego.NTLMInitiator{
			User:      c.Username,
			Domain:    c.Domain,
			LocalUser: false, // Don't assume local user
		}

		// Use hash if available, otherwise use password
		if c.NTLMHash != "" {
			processor := common.NewNTLMHashProcessor()
			ntHash, err := processor.ProcessHashForSMB(c.NTLMHash)
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

		options.Initiator = ntlmInitiator
	} else {
		// Default to null session if no credentials provided
		options.Initiator = &spnego.NTLMInitiator{
			NullSession: true,
		}
	}

	// Attempt connection
	session, err := gosmb.NewConnection(options)
	if err != nil {
		// Even if connection failed, try to extract server info from NTLM challenge
		if session != nil {
			c.session = session
			// Use the existing server info extraction logic
			if err := c.extractServerInfoWithContext(ctx); err != nil {
				log := svc1log.FromContext(ctx)
				log.Debug("Failed to extract server info from failed connection", svc1log.SafeParam("error", err))
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

	// Extract server information
	if err := c.extractServerInfoWithContext(ctx); err != nil {
		log.Warn("Failed to extract server info", svc1log.SafeParam("error", err))
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
func (c *Client) GetServerInfo() *ServerInfo {
	return c.serverInfo
}

// TestCredentials tests if the provided credentials are valid
func (c *Client) TestCredentials(username, password, domain string) (bool, string, error) {
	// Create temporary client for credential testing
	testClient := NewClient(c.Host, c.Port)
	testClient.SetCredentials(username, password, domain)
	testClient.Timeout = c.Timeout

	err := testClient.Connect()
	if err != nil {
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
func (c *Client) EnumerateShares() ([]*ShareInfo, error) {
	return c.EnumerateSharesWithContext(context.Background())
}

// EnumerateSharesWithContext lists available shares using TreeConnect testing with context
func (c *Client) EnumerateSharesWithContext(ctx context.Context) ([]*ShareInfo, error) {
	if !c.isConnected {
		return nil, fmt.Errorf("not connected to SMB server")
	}

	commonShares := []string{"C$", "D$", "E$", "ADMIN$", "IPC$", "PRINT$", "FAX$", "SYSVOL", "NETLOGON", "Users", "Public", "Share", "Data", "Files", "Shared", "Transfer", "Backup", "Archive", "Home", "Homes"}
	var shares []*ShareInfo

	log := svc1log.FromContext(ctx)
	log.Info("Testing common share names for accessibility", svc1log.SafeParam("shareCount", len(commonShares)))

	for _, shareName := range commonShares {
		shareInfo := &ShareInfo{
			Name:            shareName,
			Type:            c.determineShareType(shareName),
			Accessible:      false,
			Access:          "No Access",
			AnonymousAccess: c.UseAnonymous || c.UseNullSession,
			GuestAccess:     false,
			Hidden:          strings.HasSuffix(shareName, "$"),
		}

		// Test share accessibility
		err := c.session.TreeConnect(shareName)
		if err == nil {
			// Share is accessible
			shareInfo.Accessible = true
			shareInfo.Access = "Read" // Assume read access if TreeConnect succeeded
			_ = c.session.TreeDisconnect(shareName)

		}

		shares = append(shares, shareInfo)
	}

	log.Info("Share enumeration completed",
		svc1log.SafeParam("totalShares", len(shares)),
		svc1log.SafeParam("accessibleShares", c.countAccessibleShares(shares)))
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

// extractServerInfo extracts server information from the SMB session
func (c *Client) extractServerInfo() error {
	return c.extractServerInfoWithContext(context.Background())
}

// extractServerInfoWithContext extracts server information from the SMB session with context
func (c *Client) extractServerInfoWithContext(ctx context.Context) error {
	if c.session == nil {
		return fmt.Errorf("no active session")
	}

	c.serverInfo = &ServerInfo{
		SigningRequired:   c.session.IsSigningRequired(),
		Capabilities:      []string{"DFS", "Leasing"},
		SupportedVersions: []string{"SMB3.0.2", "SMB3.0", "SMB2.1", "SMB2.0"},
	}

	if c.session.IsSigningRequired() {
		c.serverInfo.Capabilities = append(c.serverInfo.Capabilities, "Signing")
	}

	// Extract detailed information from NTLM target info
	targetInfo := c.session.GetTargetInfo()
	if targetInfo != nil {
		// Use DNS domain name if available, fallback to NetBIOS domain
		if targetInfo.DnsDomainName != "" {
			c.serverInfo.Domain = targetInfo.DnsDomainName
		} else if targetInfo.NBDomainName != "" {
			c.serverInfo.Domain = targetInfo.NBDomainName
		}

		// Always set NetBIOS domain name if available
		if targetInfo.NBDomainName != "" {
			c.serverInfo.NetBIOSDomainName = targetInfo.NBDomainName
		}

		// Use DNS computer name if available, fallback to NetBIOS computer name
		if targetInfo.DnsComputerName != "" {
			c.serverInfo.ServerName = targetInfo.DnsComputerName
		} else if targetInfo.NBComputerName != "" {
			c.serverInfo.ServerName = targetInfo.NBComputerName
		}

		// Parse and enhance the OS version
		if targetInfo.GuessedOSVersion != "" {
			c.serverInfo.RawOSVersion = targetInfo.GuessedOSVersion
			c.serverInfo.OSVersion = parseWindowsVersion(targetInfo.GuessedOSVersion)
		} else {
			c.serverInfo.OSVersion = "Windows Server"
		}

		log := svc1log.FromContext(ctx)
		log.Info("Extracted server info",
			svc1log.SafeParam("server", c.serverInfo.ServerName),
			svc1log.SafeParam("domain", c.serverInfo.Domain),
			svc1log.SafeParam("os", c.serverInfo.OSVersion))
	} else {
		c.serverInfo.OSVersion = "Windows Server"
		log := svc1log.FromContext(ctx)
		log.Warn("NTLM target info not available")
	}

	return nil
}

// determineShareType determines the share type based on share name patterns
func (c *Client) determineShareType(shareName string) string {
	switch {
	case shareName == "IPC$":
		return "IPC"
	case shareName == "PRINT$" || shareName == "FAX$":
		return "Print"
	case strings.HasSuffix(shareName, "$"):
		return "Disk" // Administrative shares
	default:
		return "Disk" // Regular disk shares
	}
}

// countAccessibleShares counts the number of accessible shares
func (c *Client) countAccessibleShares(shares []*ShareInfo) int {
	count := 0
	for _, share := range shares {
		if share.Accessible {
			count++
		}
	}
	return count
}

// GetSMBSession returns the underlying go-smb connection for DCE/RPC operations
func (c *Client) GetSMBSession() (*gosmb.Connection, error) {
	if !c.isConnected || c.session == nil {
		return nil, fmt.Errorf("no active SMB session")
	}
	return c.session, nil
}
