package ldap

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/Azure/go-ntlmssp"
	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	ldapfern "github.com/Method-Security/networkscan/generated/go/enumerate/ldap"
	"github.com/Method-Security/networkscan/internal/common/ntlm"
	"github.com/Method-Security/networkscan/utils"
	ldap "github.com/go-ldap/ldap/v3"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumerateLDAP implements NetworkApplicationLibrary for LDAP enumeration.
type LibraryEnumerateLDAP struct{}

// dialLDAP dials the target, wrapping the connection in TLS when the target is implicit-TLS.
// Certificates go unverified: directories routinely present private-CA or self-signed certs, and
// rejecting them would fail enumeration on exactly the hardened hosts we care about.
func dialLDAP(host string, port int, useTLS bool) (*ldap.Conn, error) {
	url := utils.FormatLDAPURL(host, port, useTLS)
	if !useTLS {
		return ldap.DialURL(url)
	}
	return ldap.DialURL(url, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})) // #nosec G402
}

// enumerateNegotiator implements NTLM negotiation for server info extraction during enumeration
type enumerateNegotiator struct {
	serverInfo *commonprotocolfern.NtlmServerInfo
	log        svc1log.Logger
}

func (en *enumerateNegotiator) Negotiate(domain, workstation string) ([]byte, error) {
	return ntlmssp.NewNegotiateMessage(domain, workstation)
}

func (en *enumerateNegotiator) ChallengeResponse(chal []byte, user, hash string) ([]byte, error) {
	// Use unified NTLM extractor
	serverInfo, err := ntlm.ExtractServerInfoFromChallenge(chal, en.log)
	if err != nil {
		return nil, fmt.Errorf("failed to extract server info from NTLM challenge: %v", err)
	}

	en.serverInfo = serverInfo

	// We don't actually want to complete the authentication, just extract server info
	// Return an empty response to avoid actually authenticating
	return []byte{}, fmt.Errorf("enumeration server info extraction completed, authentication not required")
}

// extractServerInfoFromNTLMChallenge extracts server information via NTLM challenge during enumeration
func (l *LibraryEnumerateLDAP) extractServerInfoFromNTLMChallenge(ctx context.Context, host string, port int, useTLS bool, target string) *commonprotocolfern.LdapServerInfo {
	log := svc1log.FromContext(ctx)
	log.Debug("Extracting LDAP server info via NTLM challenge for enumeration", svc1log.SafeParam("target", target))

	conn, err := dialLDAP(host, port, useTLS)
	if err != nil {
		log.Debug("Failed to connect to LDAP server for server info extraction", svc1log.SafeParam("error", err.Error()))
		return nil
	}
	defer func() { _ = conn.Close() }()

	// Create enumeration negotiator to capture server info
	negotiator := &enumerateNegotiator{
		log: log,
	}

	// Attempt NTLM bind to trigger challenge/response and extract server info
	req := &ldap.NTLMBindRequest{
		Domain:     "",      // Let the server provide domain info
		Username:   "probe", // Dummy username for enumeration (same as probe)
		Password:   "probe", // Dummy password for enumeration (same as probe)
		Negotiator: negotiator,
	}

	// We expect this to fail, but we should capture the server info from the challenge
	_, err = conn.NTLMChallengeBind(req)

	// Check if we successfully extracted server info even if bind failed
	if negotiator.serverInfo != nil {
		// Convert unified server info to LDAP-specific format
		ldapServerInfo := ntlm.ConvertToLDAPServerInfo(negotiator.serverInfo)
		log.Debug("Successfully extracted server info from NTLM challenge during enumeration",
			svc1log.SafeParam("domain", ntlm.GetLDAPDomainName(ldapServerInfo)),
			svc1log.SafeParam("serverName", ntlm.GetLDAPServerName(ldapServerInfo)))
		return ldapServerInfo
	}

	log.Debug("Could not extract server info from NTLM challenge during enumeration")
	return nil
}

// authTestResult holds the result of an authentication test
type authTestResult struct {
	success       bool
	conn          *ldap.Conn
	allowedMethod bool
	authMethod    commonprotocolfern.LdapAuthMethod
}

// authenticationState holds the overall state of authentication testing
type authenticationState struct {
	connectionSuccessful bool
	workingConnection    *ldap.Conn
	anonymousAllowed     bool
	nullBindAllowed      bool
	supportedMethods     []commonprotocolfern.LdapAuthMethod
	serverInfo           *commonprotocolfern.LdapServerInfo
}

// testNullBind tests null bind (no credentials)
func (l *LibraryEnumerateLDAP) testNullBind(ctx context.Context, host string, port int, useTLS bool, target string) authTestResult {
	log := svc1log.FromContext(ctx)
	log.Debug("Testing LDAP null bind", svc1log.SafeParam("target", target))

	conn, err := dialLDAP(host, port, useTLS)
	if err != nil {
		log.Debug("Failed to connect to LDAP server", svc1log.SafeParam("error", err.Error()))
		return authTestResult{
			success:       false,
			allowedMethod: false,
			authMethod:    commonprotocolfern.LdapAuthMethodNullBind,
		}
	}

	// Attempt null bind (empty DN and password)
	err = conn.Bind("", "")
	if err != nil {
		log.Debug("Null bind failed", svc1log.SafeParam("error", err.Error()))
		_ = conn.Close()
		return authTestResult{
			success:       false,
			conn:          nil,
			allowedMethod: false,
			authMethod:    commonprotocolfern.LdapAuthMethodNullBind,
		}
	}

	log.Debug("Null bind successful")
	return authTestResult{
		success:       true,
		conn:          conn,
		allowedMethod: true,
		authMethod:    commonprotocolfern.LdapAuthMethodNullBind,
	}
}

// testAnonymousBind tests anonymous bind
func (l *LibraryEnumerateLDAP) testAnonymousBind(ctx context.Context, host string, port int, useTLS bool, target string) authTestResult {
	log := svc1log.FromContext(ctx)
	log.Debug("Testing LDAP anonymous bind", svc1log.SafeParam("target", target))

	conn, err := dialLDAP(host, port, useTLS)
	if err != nil {
		log.Debug("Failed to connect to LDAP server", svc1log.SafeParam("error", err.Error()))
		return authTestResult{
			success:       false,
			allowedMethod: false,
			authMethod:    commonprotocolfern.LdapAuthMethodAnonymous,
		}
	}

	// Attempt unauthenticated bind (no bind call)
	// Try to search rootDSE to test if anonymous access works
	searchRequest := ldap.NewSearchRequest(
		"", // Base DN (empty for rootDSE)
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)", // Filter
		[]string{},        // Attributes
		nil,
	)

	_, err = conn.Search(searchRequest)
	if err != nil {
		log.Debug("Anonymous bind/search failed", svc1log.SafeParam("error", err.Error()))
		_ = conn.Close()
		return authTestResult{
			success:       false,
			conn:          nil,
			allowedMethod: false,
			authMethod:    commonprotocolfern.LdapAuthMethodAnonymous,
		}
	}

	log.Debug("Anonymous bind successful")
	return authTestResult{
		success:       true,
		conn:          conn,
		allowedMethod: true,
		authMethod:    commonprotocolfern.LdapAuthMethodAnonymous,
	}
}

// performAuthentication performs all authentication tests
func (l *LibraryEnumerateLDAP) performAuthentication(ctx context.Context, host string, port int, useTLS bool, target string) authenticationState {
	log := svc1log.FromContext(ctx)
	log.Debug("Starting LDAP authentication testing", svc1log.SafeParam("target", target))

	state := authenticationState{
		connectionSuccessful: false,
		supportedMethods:     []commonprotocolfern.LdapAuthMethod{},
	}

	// Extract server info first using NTLM challenge
	state.serverInfo = l.extractServerInfoFromNTLMChallenge(ctx, host, port, useTLS, target)

	// Test null bind
	nullResult := l.testNullBind(ctx, host, port, useTLS, target)
	if nullResult.success {
		state.connectionSuccessful = true
		state.nullBindAllowed = true
		state.workingConnection = nullResult.conn
		state.supportedMethods = append(state.supportedMethods, commonprotocolfern.LdapAuthMethodNullBind)
		log.Debug("Null bind allowed")
	} else if nullResult.allowedMethod {
		state.supportedMethods = append(state.supportedMethods, commonprotocolfern.LdapAuthMethodNullBind)
	}

	// Test anonymous bind if null bind failed
	if !state.connectionSuccessful {
		anonResult := l.testAnonymousBind(ctx, host, port, useTLS, target)
		if anonResult.success {
			state.connectionSuccessful = true
			state.anonymousAllowed = true
			state.workingConnection = anonResult.conn
			state.supportedMethods = append(state.supportedMethods, commonprotocolfern.LdapAuthMethodAnonymous)
			log.Debug("Anonymous bind allowed")
		} else if anonResult.allowedMethod {
			state.supportedMethods = append(state.supportedMethods, commonprotocolfern.LdapAuthMethodAnonymous)
		}
	}

	log.Debug("LDAP authentication testing completed",
		svc1log.SafeParam("connectionSuccessful", state.connectionSuccessful),
		svc1log.SafeParam("nullBindAllowed", state.nullBindAllowed),
		svc1log.SafeParam("anonymousAllowed", state.anonymousAllowed))

	return state
}

// extractLdapInfo extracts LDAP-specific information from the connection
func (l *LibraryEnumerateLDAP) extractLdapInfo(ctx context.Context, conn *ldap.Conn, serverInfo *commonprotocolfern.LdapServerInfo, target string, log svc1log.Logger) {
	if conn == nil || serverInfo == nil {
		return
	}

	log.Debug("Extracting LDAP server information", svc1log.SafeParam("target", target))

	// Search for rootDSE to get server information
	searchRequest := ldap.NewSearchRequest(
		"", // Base DN (empty for rootDSE)
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)", // Filter
		[]string{
			"defaultNamingContext",
			"schemaNamingContext",
			"configurationNamingContext",
			"supportedLDAPVersion",
			"supportedSASLMechanisms",
			"supportedCapabilities",
		}, // Attributes
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Debug("Failed to search rootDSE", svc1log.SafeParam("error", err.Error()))
		return
	}

	if len(sr.Entries) > 0 {
		entry := sr.Entries[0]

		if attr := entry.GetAttributeValue("defaultNamingContext"); attr != "" {
			serverInfo.DefaultNamingContext = &attr
		}
		if attr := entry.GetAttributeValue("schemaNamingContext"); attr != "" {
			serverInfo.SchemaNamingContext = &attr
		}
		if attr := entry.GetAttributeValue("configurationNamingContext"); attr != "" {
			serverInfo.ConfigurationNamingContext = &attr
		}

		// Get multi-valued attributes
		if attrs := entry.GetAttributeValues("supportedLDAPVersion"); len(attrs) > 0 {
			serverInfo.SupportedLdapVersion = attrs
		}
		if attrs := entry.GetAttributeValues("supportedSASLMechanisms"); len(attrs) > 0 {
			serverInfo.SupportedSaslMechanisms = attrs
		}
		if attrs := entry.GetAttributeValues("supportedCapabilities"); len(attrs) > 0 {
			serverInfo.SupportedCapabilities = attrs
		}

		log.Debug("Successfully extracted LDAP server information",
			svc1log.SafeParam("defaultNamingContext", serverInfo.DefaultNamingContext))
	}
}

// assembleResponse assembles the final response
func (l *LibraryEnumerateLDAP) assembleResponse(details *ldapfern.EnumerateLdapDetails, state authenticationState) {
	// Set server info (already populated with NTLM + LDAP details)
	if state.serverInfo != nil {
		// Add authentication results to serverInfo
		state.serverInfo.NullBindAllowed = &state.nullBindAllowed
		state.serverInfo.AnonymousBindAllowed = &state.anonymousAllowed
		details.ServerInfo = state.serverInfo
	}

	// Set authentication methods at the details level
	details.AuthMethods = state.supportedMethods
}

// EnumerateTarget performs LDAP enumeration for the given target
func (l *LibraryEnumerateLDAP) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	var details ldapfern.EnumerateLdapDetails
	var errors []string

	log := svc1log.FromContext(ctx)
	log.Info("Starting LDAP enumeration for target", svc1log.SafeParam("target", target))

	host, port, useTLS := utils.ResolveLDAPTarget(target)
	// Set the actual connection target (ip:port)
	details.Target = utils.FormatHostPort(host, port)

	// Perform all authentication tests
	authState := l.performAuthentication(ctx, host, port, useTLS, target)

	// If all connections failed, log the error
	if !authState.connectionSuccessful {
		errors = append(errors, fmt.Sprintf("All connection methods failed for %s", target))
	} else {
		// Extract LDAP-specific information into serverInfo
		if authState.serverInfo != nil {
			l.extractLdapInfo(ctx, authState.workingConnection, authState.serverInfo, target, log)
		}
	}

	// Close the connection at the very end after all operations are complete
	if authState.workingConnection != nil {
		defer func() { _ = authState.workingConnection.Close() }()
	}

	// Assemble the final response
	l.assembleResponse(&details, authState)

	log.Info("LDAP enumeration completed", svc1log.SafeParam("target", target))

	return &enumeratefern.EnumerateServiceDetails{EnumerateLdapDetails: &details}, errors
}
