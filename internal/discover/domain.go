package discover

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	ldappentest "github.com/Method-Security/networkscan/internal/pentest/ldap"
	smbclient "github.com/Method-Security/networkscan/internal/protocol/smb"
	"github.com/Method-Security/networkscan/utils"
	"github.com/go-ldap/ldap/v3"
	"github.com/miekg/dns"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// RunDomainDiscovery performs enhanced domain discovery:
// 1. Try LDAP/SMB to get domain name
// 2. DNS lookup to find all domain controllers
// 3. Return domain details with all DCs
func RunDomainDiscovery(ctx context.Context, config discoverfern.DiscoverDomainConfig) (*discoverfern.DiscoverDomainReport, error) {
	log := svc1log.FromContext(ctx)

	var errors []string
	var domainInfo *discoverfern.DomainInfo

	log.Info("Starting enhanced domain discovery", svc1log.SafeParam("target", config.Target))

	host, _ := utils.ParseHostPort(config.Target, 0)

	// Step 1: Try to discover domain name using SMB first, then LDAP
	var domainName string
	var extractedInfo *basicDomainInfo

	// Try SMB first
	if smbInfo := discoverViaSMB(ctx, host); smbInfo != nil {
		extractedInfo = smbInfo
		domainName = smbInfo.dnsDomainName
		log.Info("Domain discovered via SMB", svc1log.SafeParam("domain", domainName))
	}

	// If SMB failed or didn't get domain, try LDAP
	if domainName == "" {
		if ldapInfo := discoverViaLDAP(ctx, host); ldapInfo != nil {
			extractedInfo = ldapInfo
			domainName = ldapInfo.dnsDomainName
			log.Info("Domain discovered via LDAP", svc1log.SafeParam("domain", domainName))
		}
	}

	if domainName == "" {
		errors = append(errors, "Could not discover domain name using SMB or LDAP")
	} else {
		// Step 2: Use DNS to find all domain controllers
		log.Info("Enumerating domain controllers via DNS", svc1log.SafeParam("domain", domainName))
		domainControllers, dnsErrors := enumerateDomainControllers(ctx, host, domainName, extractedInfo)
		errors = append(errors, dnsErrors...)

		// Step 3: Build the domain info with discovered information
		domainInfo = &discoverfern.DomainInfo{
			DnsDomainName:     &domainName,
			ForestName:        &domainName,
			DomainControllers: domainControllers,
		}

		// Add extracted info if available
		if extractedInfo != nil {
			if extractedInfo.netbiosDomainName != "" {
				domainInfo.NetBiosDomainName = &extractedInfo.netbiosDomainName
			}
		}

		log.Info("Domain discovery completed",
			svc1log.SafeParam("domain", domainName),
			svc1log.SafeParam("domainControllers", len(domainControllers)))
	}

	result := discoverfern.DiscoverDomainResult{
		DomainInfo: domainInfo,
	}

	report := &discoverfern.DiscoverDomainReport{
		Config: &config,
		Result: &result,
		Errors: errors,
	}

	return report, nil
}

// basicDomainInfo holds extracted domain information from SMB/LDAP
type basicDomainInfo struct {
	netbiosDomainName string
	dnsDomainName     string
}

// discoverViaSMB attempts to discover domain information via SMB
func discoverViaSMB(ctx context.Context, host string) *basicDomainInfo {
	log := svc1log.FromContext(ctx)

	log.Debug("Attempting SMB domain discovery", svc1log.SafeParam("host", host))

	// Create SMB client
	client := smbclient.NewClient(host, 445)
	client.Timeout = 30 * time.Second

	// Try to extract server info from NTLM challenge
	serverInfo, err := client.ExtractServerInfoFromChallenge(ctx)
	if err != nil {
		log.Debug("Failed to extract server info from SMB", svc1log.SafeParam("error", err))
		return nil
	}

	if serverInfo == nil {
		log.Debug("No server info available from SMB")
		return nil
	}

	info := &basicDomainInfo{}

	// Extract domain names from server info

	// Set DNS domain name
	if serverInfo.Domain != "" {
		info.dnsDomainName = serverInfo.Domain
	}

	// Set NetBIOS domain name from the dedicated field
	if serverInfo.NetBIOSDomainName != "" {
		info.netbiosDomainName = serverInfo.NetBIOSDomainName
	}

	// Close the client
	_ = client.Close()

	log.Debug("SMB domain discovery successful",
		svc1log.SafeParam("dnsDomain", info.dnsDomainName),
		svc1log.SafeParam("netbiosDomain", info.netbiosDomainName))

	return info
}

// discoverViaLDAP attempts to discover domain information via LDAP
func discoverViaLDAP(ctx context.Context, host string) *basicDomainInfo {
	log := svc1log.FromContext(ctx)

	log.Debug("Attempting LDAP domain discovery", svc1log.SafeParam("host", host))

	// Try both standard LDAP (389) and LDAPS (636)
	ports := []int{389, 636}
	var conn *ldap.Conn
	var err error

	for _, port := range ports {
		target := &ldappentest.Target{
			Host:   host,
			Port:   port,
			UseSSL: port == 636,
		}

		// Test connection first
		if err := ldappentest.TestConnection(ctx, target, 30); err != nil {
			log.Debug("LDAP connection failed", svc1log.SafeParam("port", port), svc1log.SafeParam("error", err))
			continue
		}

		// Create connection for rootDSE query
		conn, err = createLDAPConnection(target, 30)
		if err != nil {
			log.Debug("Failed to create LDAP connection", svc1log.SafeParam("port", port), svc1log.SafeParam("error", err))
			continue
		}
		break
	}

	if conn == nil {
		log.Debug("No LDAP connection could be established")
		return nil
	}
	defer func() { _ = conn.Close() }()

	// Try anonymous bind
	if err := conn.UnauthenticatedBind(""); err != nil {
		if err := conn.Bind("", ""); err != nil {
			log.Debug("LDAP bind failed", svc1log.SafeParam("error", err))
			return nil
		}
	}

	// Query rootDSE for domain information
	searchRequest := ldap.NewSearchRequest(
		"", // Base DN (empty for rootDSE)
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,  // No size limit
		30, // Time limit
		false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "rootDomainNamingContext"}, // Attributes
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		log.Debug("rootDSE query failed", svc1log.SafeParam("error", err))
		return nil
	}

	if len(searchResult.Entries) == 0 {
		log.Debug("No rootDSE entry found")
		return nil
	}

	entry := searchResult.Entries[0]
	info := &basicDomainInfo{}

	// Extract domain information from rootDSE
	if defaultNC := entry.GetAttributeValue("defaultNamingContext"); defaultNC != "" {
		// Convert DC=domain,DC=com to domain.com
		if dnsDomain := dcToDomainName(defaultNC); dnsDomain != "" {
			info.dnsDomainName = dnsDomain
		}
	}

	// Extract domain names (computer names not needed)

	// If we have a DNS domain, try to extract NetBIOS domain name
	if info.dnsDomainName != "" {
		parts := strings.Split(info.dnsDomainName, ".")
		if len(parts) > 0 {
			info.netbiosDomainName = strings.ToUpper(parts[0])
		}
	}

	log.Debug("LDAP domain discovery successful",
		svc1log.SafeParam("dnsDomain", info.dnsDomainName))

	return info
}

// enumerateDomainControllers uses DNS to find all domain controllers for a domain
func enumerateDomainControllers(ctx context.Context, host string, domainName string, knownDomainInfo *basicDomainInfo) ([]*discoverfern.DomainControllerInfo, []string) {
	log := svc1log.FromContext(ctx)
	var errors []string
	var domainControllers []*discoverfern.DomainControllerInfo

	// Query for _ldap._tcp.domain SRV records (indicates domain controllers)
	query := fmt.Sprintf("_ldap._tcp.%s.", domainName)

	c := dns.Client{
		Timeout: 30 * time.Second,
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(query), dns.TypeSRV)

	// Try querying the target host first (likely a DC), then fallback to public DNS
	dnsServers := []string{
		fmt.Sprintf("%s:53", host), // Query the target host directly
		"8.8.8.8:53",               // Fallback to public DNS
		"1.1.1.1:53",               // Fallback to Cloudflare DNS
	}

	var r *dns.Msg
	var queryErr error

	for _, dnsServer := range dnsServers {
		log.Debug("Querying DNS for domain controllers",
			svc1log.SafeParam("query", query),
			svc1log.SafeParam("server", dnsServer))

		r, _, queryErr = c.Exchange(m, dnsServer)
		if queryErr == nil && len(r.Answer) > 0 {
			log.Debug("DNS query successful", svc1log.SafeParam("server", dnsServer))
			break
		}
		log.Debug("DNS query failed or no results",
			svc1log.SafeParam("server", dnsServer),
			svc1log.SafeParam("error", queryErr))
	}

	if queryErr != nil {
		errors = append(errors, fmt.Sprintf("DNS query failed against all servers: %v", queryErr))
		return domainControllers, errors
	}

	// Process SRV records
	for _, answer := range r.Answer {
		if srv, ok := answer.(*dns.SRV); ok {
			hostname := strings.TrimSuffix(srv.Target, ".")

			dcInfo := &discoverfern.DomainControllerInfo{
				Hostname: &hostname,
			}

			// Try to resolve hostname to IP
			var ipAddress string
			if ips, err := net.LookupIP(hostname); err == nil && len(ips) > 0 {
				ipAddress = ips[0].String()
				dcInfo.IpAddress = &ipAddress
			}

			// If DNS resolution failed, use the original target IP
			if ipAddress == "" {
				ipAddress = host
				dcInfo.IpAddress = &ipAddress
			}

			// Gather detailed information about this DC using SMB
			dcDetails := gatherDomainControllerDetails(ctx, hostname, ipAddress)

			if dcDetails != nil {
				if dcDetails.serverVersion != "" {
					dcInfo.ServerVersion = &dcDetails.serverVersion
				}
				// Use the IP from SMB if we didn't get it from DNS resolution
				if dcInfo.IpAddress == nil && dcDetails.ipAddress != "" {
					dcInfo.IpAddress = &dcDetails.ipAddress
				}
			}

			domainControllers = append(domainControllers, dcInfo)
			log.Debug("Found domain controller",
				svc1log.SafeParam("hostname", hostname),
				svc1log.SafeParam("ip", dcInfo.IpAddress),
				svc1log.SafeParam("serverVersion", dcInfo.ServerVersion))
		}
	}

	if len(domainControllers) == 0 {
		errors = append(errors, fmt.Sprintf("No domain controllers found for domain %s", domainName))
	}

	return domainControllers, errors
}

// domainControllerDetails holds detailed information about a domain controller
type domainControllerDetails struct {
	serverVersion string
	ipAddress     string
}

// gatherDomainControllerDetails attempts to gather detailed information about a DC using SMB
func gatherDomainControllerDetails(ctx context.Context, hostname, ipAddress string) *domainControllerDetails {
	log := svc1log.FromContext(ctx)

	// Try multiple connection approaches
	targets := []string{}

	// Add IP address first if available (most reliable)
	if ipAddress != "" {
		targets = append(targets, ipAddress)
	}

	// Then try hostname
	if hostname != "" {
		targets = append(targets, hostname)
	}

	for _, target := range targets {
		log.Debug("Attempting to gather DC details via SMB", svc1log.SafeParam("target", target))

		// Create SMB client
		client := smbclient.NewClient(target, 445)
		client.Timeout = 10 * time.Second // Shorter timeout for DC probing

		// Try to extract server info from NTLM challenge
		serverInfo, err := client.ExtractServerInfoFromChallenge(ctx)
		if err != nil {
			log.Debug("Failed to extract server info from DC",
				svc1log.SafeParam("target", target),
				svc1log.SafeParam("error", err))
			_ = client.Close()
			continue // Try next target
		}

		if serverInfo == nil {
			log.Debug("No server info available from DC", svc1log.SafeParam("target", target))
			_ = client.Close()
			continue // Try next target
		}

		details := &domainControllerDetails{
			serverVersion: serverInfo.OSVersion,
			ipAddress:     target, // Store the target we used to connect
		}

		// Close the client
		_ = client.Close()

		log.Debug("Successfully gathered DC details",
			svc1log.SafeParam("target", target),
			svc1log.SafeParam("serverVersion", details.serverVersion))

		return details
	}

	log.Debug("Failed to gather DC details from any target",
		svc1log.SafeParam("hostname", hostname),
		svc1log.SafeParam("ipAddress", ipAddress))
	return nil
}

// Helper functions

// createLDAPConnection creates an LDAP connection (similar to the one in ldap/auth.go)
func createLDAPConnection(target *ldappentest.Target, timeout int) (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", target.Host, target.Port)

	if target.UseSSL {
		return ldap.DialTLS("tcp", address, nil)
	}

	conn, err := ldap.Dial("tcp", address)
	if err != nil {
		return nil, err
	}

	if target.UseTLS {
		if err := conn.StartTLS(nil); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("failed to start TLS: %v", err)
		}
	}

	return conn, nil
}

// dcToDomainName converts "DC=domain,DC=com" to "domain.com"
func dcToDomainName(dn string) string {
	parts := strings.Split(dn, ",")
	var domainParts []string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "dc=") {
			dcValue := strings.TrimPrefix(part, "DC=")
			dcValue = strings.TrimPrefix(dcValue, "dc=")
			domainParts = append(domainParts, dcValue)
		}
	}

	if len(domainParts) > 0 {
		return strings.Join(domainParts, ".")
	}

	return ""
}
