// Package slp implements SLP (Service Location Protocol) enumeration.
package slp

import (
	"context"
	"fmt"
	"net"
	"time"

	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	slpfern "github.com/Method-Security/networkscan/generated/go/enumerate/slp"
	slplib "github.com/Method-Security/networkscan/internal/protocol/slp"
)

// LibraryEnumerateSLP implements NetworkApplicationLibrary for SLP enumeration.
type LibraryEnumerateSLP struct{}

// EnumerateTarget performs SLP enumeration against a target:
// 1. Discover Directory Agents
// 2. Query for all service types
// 3. Enumerate service instances per type
// 4. Pull attributes for each service instance
func (s *LibraryEnumerateSLP) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	var details slpfern.EnumerateSlpDetails
	details.Target = target
	errors := []string{}

	host, _, err := net.SplitHostPort(target)
	if err != nil {
		errMsg := fmt.Sprintf("invalid target format %q: %v", target, err)
		details.Error = &errMsg
		return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSlpDetails(&details), errors
	}

	// Determine timeout from context deadline
	queryTimeout := 5 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		queryTimeout = remaining / 4
		if queryTimeout < 2*time.Second {
			queryTimeout = 2 * time.Second
		}
	}

	// Step 1: Discover Directory Agents (short timeout — no DA is common)
	daTimeout := 3 * time.Second
	das, err := slplib.DiscoverDAs(target, daTimeout)
	if err != nil {
		errors = append(errors, fmt.Sprintf("DA discovery failed: %v", err))
	}

	// Determine query target: use DA if found, otherwise use original target
	queryTarget := target
	if len(das) > 0 {
		daAddr := das[0].Address
		if parsed := extractHostFromDAURL(daAddr); parsed != "" {
			queryTarget = net.JoinHostPort(parsed, fmt.Sprintf("%d", slplib.DefaultPort))
		}
	}

	// Step 2: Query service types
	serviceTypes, err := slplib.QueryServiceTypes(queryTarget, queryTimeout)
	if err != nil {
		errors = append(errors, fmt.Sprintf("service type query failed for %s: %v", host, err))
	}

	// Step 3: Enumerate instances per type
	var allServices []slplib.ServiceEntry
	for _, svcType := range serviceTypes {
		if ctx.Err() != nil {
			errors = append(errors, "context cancelled during enumeration")
			break
		}

		services, err := slplib.QueryServices(queryTarget, svcType, queryTimeout)
		if err != nil {
			errors = append(errors, fmt.Sprintf("service query failed for type %q: %v", svcType, err))
			continue
		}
		allServices = append(allServices, services...)
	}

	// Step 4: Pull attributes for each service (shorter timeout — best effort)
	attrTimeout := 3 * time.Second
	var attrFailCount int
	for i := range allServices {
		if ctx.Err() != nil {
			break
		}

		attrs, err := slplib.QueryAttributes(queryTarget, allServices[i].ServiceURL, attrTimeout)
		if err != nil {
			attrFailCount++
			continue
		}
		allServices[i].Attributes = attrs
	}
	if attrFailCount > 0 {
		errors = append(errors, fmt.Sprintf("attribute query failed for %d/%d services", attrFailCount, len(allServices)))
	}

	// Convert to Fern types
	for _, da := range das {
		details.DirectoryAgents = append(details.DirectoryAgents, slplib.ToSlpDirectoryEntry(da))
	}
	details.ServiceTypes = serviceTypes
	for _, svc := range allServices {
		details.Services = append(details.Services, slplib.ToSlpServiceEntry(svc))
	}

	// Collect all unique scopes
	details.Scopes = collectScopes(das, allServices)

	return enumeratefern.NewEnumerateServiceDetailsFromEnumerateSlpDetails(&details), errors
}

// collectScopes aggregates unique scopes from DAs and service entries.
func collectScopes(das []slplib.DAInfo, services []slplib.ServiceEntry) []string {
	seen := make(map[string]bool)
	var scopes []string

	for _, da := range das {
		for _, scope := range da.Scopes {
			if !seen[scope] {
				seen[scope] = true
				scopes = append(scopes, scope)
			}
		}
	}
	for _, svc := range services {
		for _, scope := range svc.Scopes {
			if !seen[scope] {
				seen[scope] = true
				scopes = append(scopes, scope)
			}
		}
	}

	return scopes
}

// extractHostFromDAURL extracts the host from a DA URL like "service:directory-agent://192.168.1.10".
func extractHostFromDAURL(daURL string) string {
	// Try to find :// and extract host
	idx := 0
	for i := 0; i < len(daURL)-2; i++ {
		if daURL[i] == ':' && daURL[i+1] == '/' && daURL[i+2] == '/' {
			idx = i + 3
			break
		}
	}
	if idx == 0 {
		return daURL
	}

	host := daURL[idx:]
	// Strip trailing path
	for i, c := range host {
		if c == '/' || c == ':' {
			host = host[:i]
			break
		}
	}
	return host
}
