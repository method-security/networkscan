package msrpc

import (
	"context"
	"errors"
	"fmt"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	epm "github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
	samr "github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const (
	// BuiltinDomainName is the well-known SAM domain for local groups (aliases)
	BuiltinDomainName = "Builtin"
	// AdministratorsRID is the RID of the local Administrators alias (S-1-5-32-544)
	AdministratorsRID = uint32(544)
)

// LocalGroupMemberInfo represents a member of a local group discovered via SAM-R
type LocalGroupMemberInfo struct {
	SID string
}

// UserEntry represents a domain user with RID information for SID construction
type UserEntry struct {
	Username string
	RID      uint32
}

// DomainInfo represents domain information including SID and users
type DomainInfo struct {
	DomainSID   *dtyp.SID
	UserEntries []UserEntry
}

// SAMRClient provides functionality for interacting with the SAM Remote protocol
type SAMRClient struct {
	Host        string
	AuthOptions []dcerpc.Option
}

// NewSAMRClient creates a new SAMR client with dcerpc auth options
func NewSAMRClient(host string, authOptions []dcerpc.Option) *SAMRClient {
	return &SAMRClient{
		Host:        host,
		AuthOptions: authOptions,
	}
}

// EnumerateDomainUsers connects to SAMR and enumerates all users with RID info
func (c *SAMRClient) EnumerateDomainUsers(ctx context.Context, domain string) (*DomainInfo, error) {
	log := svc1log.FromContext(ctx)

	// Reuse existing GSSAPI context (credentials and mechanisms already set up)
	secCtx := gssapi.NewSecurityContext(ctx)

	// Use auth options for connection
	connOptions := c.AuthOptions

	// Connect to SAMR service using EPM endpoint mapper
	endpointOpts := append(connOptions, epm.EndpointMapper(secCtx, c.Host))
	conn, err := dcerpc.Dial(secCtx, c.Host, endpointOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SAMR service: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(ctx); closeErr != nil {
			log.Warn("Failed to close SAMR connection", svc1log.SafeParam("error", closeErr.Error()))
		}
	}()

	// Create SAMR client
	samrClient, err := samr.NewSamrClient(secCtx, conn, dcerpc.WithSeal())
	if err != nil {
		return nil, fmt.Errorf("failed to create SAMR client: %w", err)
	}

	// Connect to SAM server
	serverHandle, err := samrClient.Connect(secCtx, &samr.ConnectRequest{
		DesiredAccess: dtyp.AccessMaskGenericRead | dtyp.AccessMaskGenericExecute,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SAM server: %w", err)
	}

	// Look up the target domain
	domainLookup, err := samrClient.LookupDomainInSAMServer(secCtx, &samr.LookupDomainInSAMServerRequest{
		Server: serverHandle.Server,
		Name:   &dtyp.UnicodeString{Buffer: domain},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to lookup domain %s: %w", domain, err)
	}

	// Open the domain
	domainHandle, err := samrClient.OpenDomain(secCtx, &samr.OpenDomainRequest{
		Server:        serverHandle.Server,
		DesiredAccess: dtyp.AccessMaskGenericRead | dtyp.AccessMaskGenericExecute,
		DomainID:      domainLookup.DomainID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open domain %s: %w", domain, err)
	}

	// Enumerate users in domain with RID information
	var userEntries []UserEntry
	for enum := uint32(0); ; {
		users, err := samrClient.EnumerateUsersInDomain(secCtx, &samr.EnumerateUsersInDomainRequest{
			Domain:             domainHandle.Domain,
			EnumerationContext: enum,
		})
		if err != nil {
			if !errors.Is(err, ntstatus.StatusMoreEntries) {
				return nil, fmt.Errorf("failed to enumerate users in domain: %w", err)
			}
		}

		// Extract usernames and RIDs from RID enumeration
		for _, user := range users.Buffer.Buffer {
			if user.Name != nil {
				userEntry := UserEntry{
					Username: user.Name.Buffer,
					RID:      user.RelativeID,
				}
				userEntries = append(userEntries, userEntry)
			}
		}

		// Continue enumeration if more entries exist
		if enum = users.EnumerationContext; users.CountReturned == 0 || enum == 0 {
			break
		}
	}

	log.Info("Successfully enumerated domain users with RIDs via SAMR",
		svc1log.SafeParam("domain", domain),
		svc1log.SafeParam("userCount", len(userEntries)))

	// Return domain info with SID and user entries
	domainInfo := &DomainInfo{
		DomainSID:   domainLookup.DomainID,
		UserEntries: userEntries,
	}

	return domainInfo, nil
}

// EnumerateLocalGroupMembers connects to SAM-R on the target host and enumerates
// members of a local group (alias) by RID. Use AdministratorsRID (544) for the
// local Administrators group. Returns member SIDs.
func (c *SAMRClient) EnumerateLocalGroupMembers(ctx context.Context, aliasRID uint32) ([]LocalGroupMemberInfo, error) {
	log := svc1log.FromContext(ctx)

	secCtx := gssapi.NewSecurityContext(ctx)

	endpointOpts := append(c.AuthOptions, epm.EndpointMapper(secCtx, c.Host))
	conn, err := dcerpc.Dial(secCtx, c.Host, endpointOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SAMR service on %s: %w", c.Host, err)
	}
	defer func() {
		if closeErr := conn.Close(ctx); closeErr != nil {
			log.Warn("Failed to close SAMR connection", svc1log.SafeParam("error", closeErr.Error()))
		}
	}()

	samrClient, err := samr.NewSamrClient(secCtx, conn, dcerpc.WithSeal())
	if err != nil {
		return nil, fmt.Errorf("failed to create SAMR client: %w", err)
	}

	serverHandle, err := samrClient.Connect(secCtx, &samr.ConnectRequest{
		DesiredAccess: dtyp.AccessMaskGenericRead | dtyp.AccessMaskGenericExecute,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SAM server: %w", err)
	}

	// Look up the Builtin domain (contains local groups/aliases)
	builtinLookup, err := samrClient.LookupDomainInSAMServer(secCtx, &samr.LookupDomainInSAMServerRequest{
		Server: serverHandle.Server,
		Name:   &dtyp.UnicodeString{Buffer: BuiltinDomainName},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to lookup Builtin domain: %w", err)
	}

	builtinHandle, err := samrClient.OpenDomain(secCtx, &samr.OpenDomainRequest{
		Server:        serverHandle.Server,
		DesiredAccess: dtyp.AccessMaskGenericRead | dtyp.AccessMaskGenericExecute,
		DomainID:      builtinLookup.DomainID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open Builtin domain: %w", err)
	}

	// Open the alias (local group) by RID
	aliasHandle, err := samrClient.OpenAlias(secCtx, &samr.OpenAliasRequest{
		Domain:        builtinHandle.Domain,
		DesiredAccess: dtyp.AccessMaskGenericRead,
		AliasID:       aliasRID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open alias RID %d: %w", aliasRID, err)
	}

	// Get members of the alias
	membersResp, err := samrClient.GetMembersInAlias(secCtx, &samr.GetMembersInAliasRequest{
		AliasHandle: aliasHandle.AliasHandle,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get members in alias RID %d: %w", aliasRID, err)
	}

	var members []LocalGroupMemberInfo
	if membersResp.Members != nil {
		for _, sidInfo := range membersResp.Members.SIDs {
			if sidInfo.SIDPointer != nil {
				members = append(members, LocalGroupMemberInfo{
					SID: sidInfo.SIDPointer.String(),
				})
			}
		}
	}

	log.Info("Enumerated local group members via SAM-R",
		svc1log.SafeParam("host", c.Host),
		svc1log.SafeParam("aliasRID", aliasRID),
		svc1log.SafeParam("memberCount", len(members)))

	return members, nil
}
