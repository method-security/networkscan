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
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

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
	Credentials credential.Credential
}

// NewSAMRClient creates a new SAMR client
func NewSAMRClient(host string, creds credential.Credential) *SAMRClient {
	return &SAMRClient{
		Host:        host,
		Credentials: creds,
	}
}

// EnumerateDomainUsers connects to SAMR and enumerates all users with RID info
func (c *SAMRClient) EnumerateDomainUsers(ctx context.Context, domain string) (*DomainInfo, error) {
	log := svc1log.FromContext(ctx)

	// Reuse existing GSSAPI context (credentials and mechanisms already set up)
	secCtx := gssapi.NewSecurityContext(ctx)

	// Connect to SAMR service using EPM endpoint mapper
	conn, err := dcerpc.Dial(secCtx, c.Host, epm.EndpointMapper(secCtx, c.Host))
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
