package ldap

import (
	"context"
	"fmt"

	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	ldapfern "github.com/Method-Security/networkscan/generated/go/enumerate/ldap"
	"github.com/Method-Security/networkscan/utils"
	ldap "github.com/go-ldap/ldap/v3"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumerateLDAP implements NetworkApplicationLibrary for LDAP enumeration.
type LibraryEnumerateLDAP struct{}

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
}

// testNullBind tests null bind (no credentials)
func (l *LibraryEnumerateLDAP) testNullBind(ctx context.Context, host string, port int, target string) authTestResult {
	log := svc1log.FromContext(ctx)
	log.Debug("Testing LDAP null bind", svc1log.SafeParam("target", target))

	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
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
func (l *LibraryEnumerateLDAP) testAnonymousBind(ctx context.Context, host string, port int, target string) authTestResult {
	log := svc1log.FromContext(ctx)
	log.Debug("Testing LDAP anonymous bind", svc1log.SafeParam("target", target))

	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
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
func (l *LibraryEnumerateLDAP) performAuthentication(ctx context.Context, host string, port int, target string) authenticationState {
	log := svc1log.FromContext(ctx)
	log.Debug("Starting LDAP authentication testing", svc1log.SafeParam("target", target))

	state := authenticationState{
		connectionSuccessful: false,
		supportedMethods:     []commonprotocolfern.LdapAuthMethod{},
	}

	// Test null bind
	nullResult := l.testNullBind(ctx, host, port, target)
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
		anonResult := l.testAnonymousBind(ctx, host, port, target)
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
func (l *LibraryEnumerateLDAP) extractLdapInfo(ctx context.Context, conn *ldap.Conn, details *ldapfern.EnumerateLdapDetails, target string, log svc1log.Logger) {
	if conn == nil {
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
			details.DefaultNamingContext = &attr
		}
		if attr := entry.GetAttributeValue("schemaNamingContext"); attr != "" {
			details.SchemaNamingContext = &attr
		}
		if attr := entry.GetAttributeValue("configurationNamingContext"); attr != "" {
			details.ConfigurationNamingContext = &attr
		}

		// Get multi-valued attributes
		if attrs := entry.GetAttributeValues("supportedLDAPVersion"); len(attrs) > 0 {
			details.SupportedLdapVersion = attrs
		}
		if attrs := entry.GetAttributeValues("supportedSASLMechanisms"); len(attrs) > 0 {
			details.SupportedSaslMechanisms = attrs
		}
		if attrs := entry.GetAttributeValues("supportedCapabilities"); len(attrs) > 0 {
			details.SupportedCapabilities = attrs
		}

		log.Debug("Successfully extracted LDAP server information",
			svc1log.SafeParam("defaultNamingContext", details.DefaultNamingContext))
	}
}

// assembleResponse assembles the final response
func (l *LibraryEnumerateLDAP) assembleResponse(details *ldapfern.EnumerateLdapDetails, state authenticationState) {
	// Set authentication results
	details.NullBindAllowed = &state.nullBindAllowed
	details.AnonymousBindAllowed = &state.anonymousAllowed
	details.AuthMethods = state.supportedMethods
}

// EnumerateTarget performs LDAP enumeration for the given target
func (l *LibraryEnumerateLDAP) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	var details ldapfern.EnumerateLdapDetails
	details.Target = target
	var errors []string

	log := svc1log.FromContext(ctx)
	log.Info("Starting LDAP enumeration for target", svc1log.SafeParam("target", target))

	host, port := utils.ParseHostPort(target, 389)

	// Perform all authentication tests
	authState := l.performAuthentication(ctx, host, port, target)

	// If all connections failed, log the error
	if !authState.connectionSuccessful {
		errors = append(errors, fmt.Sprintf("All connection methods failed for %s", target))
	} else {
		// Extract LDAP-specific information
		l.extractLdapInfo(ctx, authState.workingConnection, &details, target, log)
	}

	// Close the connection at the very end after all operations are complete
	if authState.workingConnection != nil {
		defer func() { _ = authState.workingConnection.Close() }()
	}

	// Assemble the final response
	l.assembleResponse(&details, authState)

	log.Info("LDAP enumeration completed", svc1log.SafeParam("target", target))

	return enumeratefern.NewEnumerateServiceDetailsFromEnumerateLdapDetails(&details), errors
}
