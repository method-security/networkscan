package discover

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/common/ntlm"
	smbclient "github.com/Method-Security/networkscan/internal/protocol/smb"
	"github.com/Method-Security/networkscan/utils"
	"github.com/miekg/dns"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// Cache for SMB server info to avoid duplicate scans
var (
	smbInfoCache = make(map[string]*commonprotocolfern.SmbServerInfo)
	smbInfoMutex sync.RWMutex
)

// RunDomainDiscovery performs SMB-based domain discovery:
// 1. Use SMB challenge-only to get domain name (no authentication)
// 2. DNS lookup to find all domain controllers
// 3. Return domain details with all DCs (using cache to avoid duplicate scans)
func RunDomainDiscovery(ctx context.Context, config discoverfern.DiscoverDomainConfig) (*discoverfern.DiscoverDomainReport, error) {
	log := svc1log.FromContext(ctx)

	var errors []string
	var domainInfo *discoverfern.DomainInfo

	log.Info("Starting enhanced domain discovery", svc1log.SafeParam("target", config.Target))

	host, _ := utils.ParseHostPort(config.Target, 0)

	// Step 1: Discover domain name using SMB challenge-only (no authentication)
	var domainName string
	var extractedInfo *basicDomainInfo

	// Use SMB with challenge-only flow
	if smbInfo := discoverViaSMB(ctx, host); smbInfo != nil {
		extractedInfo = smbInfo
		domainName = smbInfo.dnsDomainName
		log.Info("Domain discovered via SMB challenge", svc1log.SafeParam("domain", domainName))
	}

	if domainName == "" {
		errors = append(errors, "Could not discover domain name using SMB challenge")
	} else {
		// Step 2: Use DNS to find all domain controllers
		log.Info("Enumerating domain controllers via DNS", svc1log.SafeParam("domain", domainName))
		domainControllers, dnsErrors := enumerateDomainControllers(ctx, host, domainName)
		errors = append(errors, dnsErrors...)

		// Step 3: Build the domain info with discovered information
		domainInfo = &discoverfern.DomainInfo{
			DomainControllers: domainControllers,
		}

		// Add extracted info if available
		if extractedInfo != nil {
			// Include the full server info from the initial target
			if extractedInfo.serverInfo != nil {
				domainInfo.ServerInfo = extractedInfo.serverInfo
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
	serverInfo        *commonprotocolfern.SmbServerInfo // Full server info from initial target
}

// discoverViaSMB attempts to discover domain information via SMB challenge-only (no authentication)
func discoverViaSMB(ctx context.Context, host string) *basicDomainInfo {
	log := svc1log.FromContext(ctx)

	log.Debug("Attempting SMB challenge-only domain discovery", svc1log.SafeParam("host", host))

	// Check cache first to avoid duplicate scans
	smbInfoMutex.RLock()
	if cachedInfo, exists := smbInfoCache[host]; exists {
		log.Debug("Using cached SMB server info for domain discovery", svc1log.SafeParam("host", host))
		smbInfoMutex.RUnlock()

		info := &basicDomainInfo{
			serverInfo: cachedInfo,
		}

		// Extract domain names from cached server info
		if domain := ntlm.GetSMBDomainName(cachedInfo); domain != "" {
			info.dnsDomainName = domain
		}
		if netbiosDomain := ntlm.GetSMBNetbiosDomain(cachedInfo); netbiosDomain != "" {
			info.netbiosDomainName = netbiosDomain
		}

		return info
	}
	smbInfoMutex.RUnlock()

	// Create SMB client
	client := smbclient.NewClient(host, 445)
	client.Timeout = 30 * time.Second
	client.SkipServerInfoExtraction(true) // We'll extract manually

	// Use challenge-only mode - no authentication, just capture NTLM challenge for server info
	client.SetChallengeOnly()          // Enable challenge-only mode
	client.SetAnonymous()              // Use anonymous credentials
	_ = client.ConnectWithContext(ctx) // Connection may fail but we get challenge data

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

	// Cache the server info to avoid duplicate scans
	smbInfoMutex.Lock()
	smbInfoCache[host] = serverInfo
	smbInfoMutex.Unlock()

	info := &basicDomainInfo{
		serverInfo: serverInfo, // Store the full server info
	}

	// Extract domain names from server info for convenience

	// Set DNS domain name
	if domain := ntlm.GetSMBDomainName(serverInfo); domain != "" {
		info.dnsDomainName = domain
	}

	// Set NetBIOS domain name from the TargetInfo structure
	if netbiosDomain := ntlm.GetSMBNetbiosDomain(serverInfo); netbiosDomain != "" {
		info.netbiosDomainName = netbiosDomain
	}

	// Close the client
	_ = client.Close()

	var dnsComputer string
	if info.serverInfo != nil && info.serverInfo.TargetInfo != nil && info.serverInfo.TargetInfo.DnsComputerName != nil {
		dnsComputer = *info.serverInfo.TargetInfo.DnsComputerName
	}

	log.Debug("SMB domain discovery successful",
		svc1log.SafeParam("dnsDomain", info.dnsDomainName),
		svc1log.SafeParam("netbiosDomain", info.netbiosDomainName),
		svc1log.SafeParam("dnsComputer", dnsComputer))

	return info
}

// enumerateDomainControllers uses DNS to find all domain controllers for a domain
func enumerateDomainControllers(ctx context.Context, host string, domainName string) ([]*discoverfern.DomainControllerInfo, []string) {
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

	// Try querying the target host first (likely a DC), then fallback to system DNS
	dnsServers := []string{
		fmt.Sprintf("%s:53", host), // Query the target host directly
	}

	// Add system DNS servers as fallback
	if systemDNS, err := getSystemDNSServers(); err == nil {
		dnsServers = append(dnsServers, systemDNS...)
	} else {
		// If we can't get system DNS, fallback to public DNS
		log.Debug("Failed to get system DNS, using public DNS fallback", svc1log.SafeParam("error", err))
		dnsServers = append(dnsServers, "8.8.8.8:53", "1.1.1.1:53")
	}

	var r *dns.Msg
	var queryErr error

	for _, dnsServer := range dnsServers {
		if dnsServer == "" {
			// Use Go's built-in system resolver for SRV records
			log.Debug("Querying DNS for domain controllers using system resolver",
				svc1log.SafeParam("query", query))

			_, srvRecords, err := net.LookupSRV("ldap", "tcp", domainName)
			if err == nil && len(srvRecords) > 0 {
				// Convert SRV records to dns.Msg format for consistent processing
				r = new(dns.Msg)
				for _, srv := range srvRecords {
					rr := &dns.SRV{
						Hdr: dns.RR_Header{
							Name:   query,
							Rrtype: dns.TypeSRV,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						Priority: srv.Priority,
						Weight:   srv.Weight,
						Port:     srv.Port,
						Target:   srv.Target,
					}
					r.Answer = append(r.Answer, rr)
				}
				queryErr = nil
				log.Debug("DNS query successful using system resolver")
				break
			} else {
				queryErr = err
				log.Debug("DNS query failed using system resolver",
					svc1log.SafeParam("error", err))
			}
		} else {
			// Use specific DNS server
			log.Debug("Querying DNS for domain controllers",
				svc1log.SafeParam("query", query),
				svc1log.SafeParam("server", dnsServer))
			r, _, queryErr = c.Exchange(m, dnsServer)

			if queryErr == nil && len(r.Answer) > 0 {
				log.Debug("DNS query successful", svc1log.SafeParam("server", dnsServer))
				break
			} else {
				log.Debug("DNS query failed or no results",
					svc1log.SafeParam("server", dnsServer),
					svc1log.SafeParam("error", queryErr))
			}
		}
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

			// Gather detailed information about this DC using SMB challenge-only
			dcDetails := gatherDomainControllerDetails(ctx, hostname, ipAddress)

			if dcDetails != nil {
				// Store the complete SMB server info in the new structure
				dcInfo.SmbServerInfo = dcDetails.smbServerInfo

				// Use the IP from SMB if we didn't get it from DNS resolution
				if dcInfo.IpAddress == nil && dcDetails.ipAddress != "" {
					dcInfo.IpAddress = &dcDetails.ipAddress
				}
			}

			domainControllers = append(domainControllers, dcInfo)
			var serverVersion string
			if dcInfo.SmbServerInfo != nil && dcInfo.SmbServerInfo.ParsedOsVersion != nil {
				serverVersion = *dcInfo.SmbServerInfo.ParsedOsVersion
			}
			log.Debug("Found domain controller",
				svc1log.SafeParam("hostname", hostname),
				svc1log.SafeParam("ip", dcInfo.IpAddress),
				svc1log.SafeParam("serverVersion", serverVersion))
		}
	}

	if len(domainControllers) == 0 {
		errors = append(errors, fmt.Sprintf("No domain controllers found for domain %s", domainName))
	}

	return domainControllers, errors
}

// domainControllerDetails holds detailed information about a domain controller
type domainControllerDetails struct {
	smbServerInfo *commonprotocolfern.SmbServerInfo
	ipAddress     string
}

// gatherDomainControllerDetails attempts to gather detailed information about a DC using SMB challenge-only
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
		log.Debug("Attempting to gather DC details via SMB challenge-only", svc1log.SafeParam("target", target))

		// Create SMB client
		client := smbclient.NewClient(target, 445)
		client.Timeout = 10 * time.Second     // Shorter timeout for DC probing
		client.SkipServerInfoExtraction(true) // We'll extract manually

		// Check cache first to avoid duplicate scans
		smbInfoMutex.RLock()
		if cachedInfo, exists := smbInfoCache[target]; exists {
			log.Debug("Using cached SMB server info", svc1log.SafeParam("target", target))
			smbInfoMutex.RUnlock()
			details := &domainControllerDetails{
				smbServerInfo: cachedInfo,
				ipAddress:     target,
			}
			return details
		}
		smbInfoMutex.RUnlock()

		// Use challenge-only mode - no authentication attempts, just capture NTLM challenge
		client.SetChallengeOnly()          // Enable challenge-only mode
		client.SetAnonymous()              // Use anonymous credentials
		_ = client.ConnectWithContext(ctx) // Connection may fail but we get challenge data

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

		// Cache the server info to avoid duplicate scans
		smbInfoMutex.Lock()
		smbInfoCache[target] = serverInfo
		smbInfoMutex.Unlock()

		// Use the unified server info directly
		details := &domainControllerDetails{
			smbServerInfo: serverInfo,
			ipAddress:     target, // Store the target we used to connect
		}

		// Close the client
		_ = client.Close()

		var osVersion string
		if serverInfo.ParsedOsVersion != nil {
			osVersion = *serverInfo.ParsedOsVersion
		}
		log.Debug("Successfully gathered DC details",
			svc1log.SafeParam("target", target),
			svc1log.SafeParam("serverVersion", osVersion))

		return details
	}

	log.Debug("Failed to gather DC details from any target",
		svc1log.SafeParam("hostname", hostname),
		svc1log.SafeParam("ipAddress", ipAddress))
	return nil
}

// Helper functions

// getSystemDNSServers uses Go's default resolver (cross-platform)
func getSystemDNSServers() ([]string, error) {
	// Just use the default system DNS resolver
	// Go will handle the platform-specific DNS configuration
	return []string{""}, nil // Empty string means use system default
}
